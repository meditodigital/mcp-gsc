from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


READONLY_GSC_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
WRITE_GSC_SCOPE = "https://www.googleapis.com/auth/webmasters"
DEFAULT_GOOGLE_SCOPES = ["openid", "email", "profile", READONLY_GSC_SCOPE]


@dataclass(frozen=True)
class ServerConfig:
    public_base_url: str
    host: str
    port: int


@dataclass(frozen=True)
class GoogleConfig:
    client_id: str
    client_secret: str
    hosted_domain: str
    scopes: list[str]


@dataclass(frozen=True)
class OAuthConfig:
    client_id: str
    client_secret: str
    redirect_uris: list[str]
    access_token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    authorization_code_ttl_seconds: int


@dataclass(frozen=True)
class SessionConfig:
    cookie_name: str
    cookie_secret: str
    ttl_seconds: int
    secure: bool


@dataclass(frozen=True)
class AppConfig:
    server: ServerConfig
    google: GoogleConfig
    oauth: OAuthConfig
    session: SessionConfig
    database_url: str
    encryption_key: str

    @property
    def gsc_scopes(self) -> list[str]:
        return [scope for scope in self.google.scopes if scope in {READONLY_GSC_SCOPE, WRITE_GSC_SCOPE}]

    @property
    def has_write_scope(self) -> bool:
        return WRITE_GSC_SCOPE in self.google.scopes


class ConfigError(ValueError):
    pass


def remote_auth_enabled(env: Mapping[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    explicit = values.get("MCP_REMOTE_AUTH", "").strip().lower()
    if explicit in {"1", "true", "yes", "on"}:
        return True
    if explicit in {"0", "false", "no", "off"}:
        return False
    return values.get("MCP_TRANSPORT", "").strip().lower() in {"streamable-http", "remote-http"}


def load_app_config(env: Mapping[str, str] | None = None) -> AppConfig:
    values = os.environ if env is None else env
    public_base_url = _required(values, "PUBLIC_BASE_URL").rstrip("/")
    google_scopes = _split_scopes(values.get("GOOGLE_SCOPES"))

    return AppConfig(
        server=ServerConfig(
            public_base_url=public_base_url,
            host=values.get("MCP_HOST") or values.get("HOST") or "0.0.0.0",
            port=_int(values.get("MCP_PORT") or values.get("PORT"), 3001, "PORT"),
        ),
        google=GoogleConfig(
            client_id=_required(values, "GOOGLE_CLIENT_ID"),
            client_secret=_required(values, "GOOGLE_CLIENT_SECRET"),
            hosted_domain=_required(values, "GOOGLE_HOSTED_DOMAIN").lower(),
            scopes=google_scopes,
        ),
        oauth=OAuthConfig(
            client_id=_required(values, "MCP_OAUTH_CLIENT_ID"),
            client_secret=_required(values, "MCP_OAUTH_CLIENT_SECRET"),
            redirect_uris=_split_csv(_required(values, "MCP_OAUTH_REDIRECT_URIS")),
            access_token_ttl_seconds=_int(values.get("MCP_ACCESS_TOKEN_TTL_SECONDS"), 3600, "MCP_ACCESS_TOKEN_TTL_SECONDS"),
            refresh_token_ttl_seconds=_int(values.get("MCP_REFRESH_TOKEN_TTL_SECONDS"), 2592000, "MCP_REFRESH_TOKEN_TTL_SECONDS"),
            authorization_code_ttl_seconds=_int(values.get("MCP_AUTHORIZATION_CODE_TTL_SECONDS"), 600, "MCP_AUTHORIZATION_CODE_TTL_SECONDS"),
        ),
        session=SessionConfig(
            cookie_name=values.get("SESSION_COOKIE_NAME", "gsc_session"),
            cookie_secret=_required(values, "SESSION_COOKIE_SECRET"),
            ttl_seconds=_int(values.get("SESSION_TTL_SECONDS"), 604800, "SESSION_TTL_SECONDS"),
            secure=_bool(values.get("SESSION_COOKIE_SECURE"), public_base_url.startswith("https://")),
        ),
        database_url=_required(values, "DATABASE_URL"),
        encryption_key=_required(values, "APP_ENCRYPTION_KEY"),
    )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if value is None or value.strip() == "":
        raise ConfigError(f"Missing required environment variable: {name}")
    return value.strip()


def _split_scopes(value: str | None) -> list[str]:
    scopes = DEFAULT_GOOGLE_SCOPES if value is None or value.strip() == "" else value.split()
    output = []
    for scope in scopes:
        if scope not in output:
            output.append(scope)
    if WRITE_GSC_SCOPE in output and READONLY_GSC_SCOPE in output:
        output.remove(READONLY_GSC_SCOPE)
    return output


def _split_csv(value: str) -> list[str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise ConfigError("MCP_OAUTH_REDIRECT_URIS must contain at least one URL")
    return items


def _int(value: str | None, default: int, name: str) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer") from error


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError("Boolean environment variables must be true or false")
