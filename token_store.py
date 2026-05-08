from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import urlparse

import psycopg
from cryptography.fernet import Fernet, InvalidToken


@dataclass(frozen=True)
class Principal:
    subject: str
    email: str
    hosted_domain: str
    display_name: str | None = None


@dataclass(frozen=True)
class GoogleFlow:
    state: str
    code_verifier: str
    nonce: str
    return_to: str
    expires_at: int


@dataclass(frozen=True)
class AuthorizationCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: list[str]
    principal: Principal


@dataclass(frozen=True)
class TokenValidation:
    client_id: str
    scopes: list[str]
    principal: Principal
    access_token_expires_at: int


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_token_expires_at: int
    refresh_token_expires_at: int


class TokenStore:
    def __init__(self, database_url: str, encryption_key: str):
        self.database_url = database_url
        self._fernet = Fernet(_normalize_fernet_key(encryption_key))
        self._sqlite_path = _sqlite_path(database_url)

    def init(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS gsc_google_auth_flows (
                state_hash TEXT PRIMARY KEY,
                code_verifier TEXT NOT NULL,
                nonce TEXT NOT NULL,
                return_to TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS gsc_google_credentials (
                subject TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                hosted_domain TEXT NOT NULL,
                display_name TEXT,
                credentials_json TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS gsc_oauth_authorization_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                scopes TEXT NOT NULL,
                subject TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER,
                created_at INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS gsc_oauth_tokens (
                access_token_hash TEXT PRIMARY KEY,
                refresh_token_hash TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                scopes TEXT NOT NULL,
                access_token_expires_at INTEGER NOT NULL,
                refresh_token_expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER
            )
            """,
            "CREATE INDEX IF NOT EXISTS gsc_oauth_tokens_refresh_idx ON gsc_oauth_tokens(refresh_token_hash)",
            "CREATE INDEX IF NOT EXISTS gsc_oauth_tokens_subject_idx ON gsc_oauth_tokens(subject)",
        ]
        with self._connection() as conn:
            for statement in statements:
                self._execute(conn, statement)

    def create_google_flow(self, state: str, code_verifier: str, nonce: str, return_to: str, ttl_seconds: int) -> None:
        now = int(time.time())
        self._execute_write(
            """
            INSERT INTO gsc_google_auth_flows (state_hash, code_verifier, nonce, return_to, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(state_hash) DO UPDATE SET
                code_verifier=excluded.code_verifier,
                nonce=excluded.nonce,
                return_to=excluded.return_to,
                expires_at=excluded.expires_at,
                created_at=excluded.created_at
            """,
            (_hash(state), code_verifier, nonce, return_to, now + ttl_seconds, now),
        )

    def consume_google_flow(self, state: str) -> GoogleFlow | None:
        now = int(time.time())
        row = self._fetch_one(
            "SELECT state_hash, code_verifier, nonce, return_to, expires_at FROM gsc_google_auth_flows WHERE state_hash=? AND expires_at>?",
            (_hash(state), now),
        )
        self._execute_write("DELETE FROM gsc_google_auth_flows WHERE state_hash=?", (_hash(state),))
        if row is None:
            return None
        return GoogleFlow(state=state, code_verifier=row["code_verifier"], nonce=row["nonce"], return_to=row["return_to"], expires_at=int(row["expires_at"]))

    def store_google_credentials(self, principal: Principal, credentials_json: str, scopes: list[str]) -> None:
        now = int(time.time())
        encrypted = self._fernet.encrypt(credentials_json.encode("utf-8")).decode("utf-8")
        self._execute_write(
            """
            INSERT INTO gsc_google_credentials (subject, email, hosted_domain, display_name, credentials_json, scopes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject) DO UPDATE SET
                email=excluded.email,
                hosted_domain=excluded.hosted_domain,
                display_name=excluded.display_name,
                credentials_json=excluded.credentials_json,
                scopes=excluded.scopes,
                updated_at=excluded.updated_at
            """,
            (principal.subject, principal.email, principal.hosted_domain, principal.display_name, encrypted, json.dumps(scopes), now, now),
        )

    def update_google_credentials(self, subject: str, credentials_json: str, scopes: list[str]) -> None:
        encrypted = self._fernet.encrypt(credentials_json.encode("utf-8")).decode("utf-8")
        self._execute_write(
            "UPDATE gsc_google_credentials SET credentials_json=?, scopes=?, updated_at=? WHERE subject=?",
            (encrypted, json.dumps(scopes), int(time.time()), subject),
        )

    def get_google_credentials(self, subject: str) -> tuple[Principal, str, list[str]] | None:
        row = self._fetch_one(
            "SELECT subject, email, hosted_domain, display_name, credentials_json, scopes FROM gsc_google_credentials WHERE subject=?",
            (subject,),
        )
        if row is None:
            return None
        try:
            credentials_json = self._fernet.decrypt(row["credentials_json"].encode("utf-8")).decode("utf-8")
        except InvalidToken as error:
            raise ValueError("Stored Google credentials could not be decrypted") from error
        return _principal_from_row(row), credentials_json, json.loads(row["scopes"])

    def create_authorization_code(self, code: str, client_id: str, redirect_uri: str, code_challenge: str, scopes: list[str], principal: Principal, ttl_seconds: int) -> None:
        self._execute_write(
            """
            INSERT INTO gsc_oauth_authorization_codes (code_hash, client_id, redirect_uri, code_challenge, scopes, subject, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (_hash(code), client_id, redirect_uri, code_challenge, json.dumps(scopes), principal.subject, int(time.time()) + ttl_seconds, int(time.time())),
        )

    def consume_authorization_code(self, code: str, client_id: str, redirect_uri: str) -> AuthorizationCode | None:
        now = int(time.time())
        row = self._fetch_one(
            """
            SELECT c.client_id, c.redirect_uri, c.code_challenge, c.scopes, g.subject, g.email, g.hosted_domain, g.display_name
            FROM gsc_oauth_authorization_codes c
            JOIN gsc_google_credentials g ON g.subject = c.subject
            WHERE c.code_hash=? AND c.client_id=? AND c.redirect_uri=? AND c.consumed_at IS NULL AND c.expires_at>?
            """,
            (_hash(code), client_id, redirect_uri, now),
        )
        self._execute_write("UPDATE gsc_oauth_authorization_codes SET consumed_at=? WHERE code_hash=?", (now, _hash(code)))
        if row is None:
            return None
        return AuthorizationCode(
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            code_challenge=row["code_challenge"],
            scopes=json.loads(row["scopes"]),
            principal=_principal_from_row(row),
        )

    def create_token_pair(self, client_id: str, principal: Principal, scopes: list[str], access_ttl: int, refresh_ttl: int) -> TokenPair:
        now = int(time.time())
        pair = TokenPair(
            access_token=_opaque_token(),
            refresh_token=_opaque_token(),
            access_token_expires_at=now + access_ttl,
            refresh_token_expires_at=now + refresh_ttl,
        )
        self._execute_write(
            """
            INSERT INTO gsc_oauth_tokens (access_token_hash, refresh_token_hash, client_id, subject, scopes, access_token_expires_at, refresh_token_expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (_hash(pair.access_token), _hash(pair.refresh_token), client_id, principal.subject, json.dumps(scopes), pair.access_token_expires_at, pair.refresh_token_expires_at, now),
        )
        return pair

    def validate_access_token(self, token: str) -> TokenValidation | None:
        row = self._fetch_one(
            """
            SELECT t.client_id, t.scopes, t.access_token_expires_at, g.subject, g.email, g.hosted_domain, g.display_name
            FROM gsc_oauth_tokens t
            JOIN gsc_google_credentials g ON g.subject = t.subject
            WHERE t.access_token_hash=? AND t.revoked_at IS NULL AND t.access_token_expires_at>?
            """,
            (_hash(token), int(time.time())),
        )
        if row is None:
            return None
        self._execute_write("UPDATE gsc_oauth_tokens SET last_used_at=? WHERE access_token_hash=?", (int(time.time()), _hash(token)))
        return TokenValidation(
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            principal=_principal_from_row(row),
            access_token_expires_at=int(row["access_token_expires_at"]),
        )

    def rotate_refresh_token(self, refresh_token: str, client_id: str, access_ttl: int, refresh_ttl: int) -> tuple[TokenPair, TokenValidation] | None:
        row = self._fetch_one(
            """
            SELECT t.scopes, g.subject, g.email, g.hosted_domain, g.display_name
            FROM gsc_oauth_tokens t
            JOIN gsc_google_credentials g ON g.subject = t.subject
            WHERE t.refresh_token_hash=? AND t.client_id=? AND t.revoked_at IS NULL AND t.refresh_token_expires_at>?
            """,
            (_hash(refresh_token), client_id, int(time.time())),
        )
        if row is None:
            return None
        self._execute_write("UPDATE gsc_oauth_tokens SET revoked_at=?, last_used_at=? WHERE refresh_token_hash=?", (int(time.time()), int(time.time()), _hash(refresh_token)))
        principal = _principal_from_row(row)
        scopes = json.loads(row["scopes"])
        pair = self.create_token_pair(client_id, principal, scopes, access_ttl, refresh_ttl)
        return pair, TokenValidation(client_id=client_id, scopes=scopes, principal=principal, access_token_expires_at=pair.access_token_expires_at)

    def revoke_token(self, token: str, client_id: str) -> None:
        self._execute_write(
            "UPDATE gsc_oauth_tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL AND (access_token_hash=? OR refresh_token_hash=?)",
            (int(time.time()), client_id, _hash(token), _hash(token)),
        )

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        if self._sqlite_path is not None:
            conn = sqlite3.connect(self._sqlite_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()
            return
        with psycopg.connect(self.database_url) as conn:
            yield conn

    def _execute_write(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self._connection() as conn:
            self._execute(conn, sql, params)

    def _fetch_one(self, sql: str, params: tuple[Any, ...] = ()) -> Any | None:
        with self._connection() as conn:
            cursor = self._execute(conn, sql, params)
            return cursor.fetchone()

    def _execute(self, conn: Any, sql: str, params: tuple[Any, ...] = ()) -> Any:
        if self._sqlite_path is not None:
            return conn.execute(sql, params)
        cursor = conn.cursor(row_factory=psycopg.rows.dict_row)
        cursor.execute(sql.replace("?", "%s"), params)
        return cursor


def _principal_from_row(row: Any) -> Principal:
    return Principal(
        subject=row["subject"],
        email=row["email"],
        hosted_domain=row["hosted_domain"],
        display_name=row["display_name"],
    )


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _opaque_token() -> str:
    return secrets.token_urlsafe(48)


def _sqlite_path(database_url: str) -> str | None:
    if database_url == "sqlite:///:memory:":
        return ":memory:"
    if database_url.startswith("sqlite:///"):
        return database_url.removeprefix("sqlite:///")
    parsed = urlparse(database_url)
    if parsed.scheme == "sqlite":
        return parsed.path
    return None


def _normalize_fernet_key(value: str) -> bytes:
    raw_value = value.strip().encode("utf-8")
    try:
        Fernet(raw_value)
        return raw_value
    except Exception:
        pass
    if len(value.strip()) == 64:
        try:
            return base64.urlsafe_b64encode(bytes.fromhex(value.strip()))
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(value.strip())
        if len(decoded) == 32:
            return base64.urlsafe_b64encode(decoded)
    except Exception:
        pass
    if len(raw_value) >= 32:
        return base64.urlsafe_b64encode(hashlib.sha256(raw_value).digest())
    raise ValueError("APP_ENCRYPTION_KEY must be a Fernet key, a 32-byte base64 value, or a 64-character hex value")
