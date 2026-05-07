from __future__ import annotations

import json
from functools import lru_cache

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from app_config import WRITE_GSC_SCOPE, AppConfig, load_app_config, remote_auth_enabled
from token_store import TokenStore, TokenValidation


class DatabaseTokenVerifier(TokenVerifier):
    def __init__(self, store: TokenStore):
        self.store = store

    async def verify_token(self, token: str) -> AccessToken | None:
        validation = self.store.validate_access_token(token)
        if validation is None:
            return None
        return AccessToken(
            token=token,
            client_id=validation.client_id,
            scopes=validation.scopes,
            expires_at=validation.access_token_expires_at,
            resource=f"{get_app_config().server.public_base_url}/mcp",
        )


def create_mcp(name: str) -> FastMCP:
    if not remote_auth_enabled():
        return FastMCP(name)
    config = get_app_config()
    store = get_token_store()
    return FastMCP(
        name,
        json_response=True,
        stateless_http=True,
        token_verifier=DatabaseTokenVerifier(store),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(config.server.public_base_url),
            resource_server_url=AnyHttpUrl(f"{config.server.public_base_url}/mcp"),
            required_scopes=["mcp"],
        ),
    )


def get_remote_gsc_credentials() -> Credentials | None:
    if not remote_auth_enabled():
        return None
    token = get_access_token()
    if token is None:
        raise RuntimeError("No authenticated MCP user is available")
    validation = _validate_current_token(token.token)
    stored = get_token_store().get_google_credentials(validation.principal.subject)
    if stored is None:
        raise RuntimeError("Connected Google account credentials were not found")
    _, credentials_json, scopes = stored
    credentials = Credentials.from_authorized_user_info(json.loads(credentials_json), scopes=scopes)
    if not credentials.valid:
        if not credentials.refresh_token:
            raise RuntimeError("Connected Google account is missing a refresh token")
        credentials.refresh(Request())
        get_token_store().update_google_credentials(validation.principal.subject, credentials.to_json(), list(credentials.granted_scopes or scopes))
    return credentials


def current_user_has_write_scope() -> bool:
    if not remote_auth_enabled():
        return True
    token = get_access_token()
    if token is None:
        return False
    validation = get_token_store().validate_access_token(token.token)
    if validation is None:
        return False
    stored = get_token_store().get_google_credentials(validation.principal.subject)
    if stored is None:
        return False
    _, _, scopes = stored
    return WRITE_GSC_SCOPE in scopes


def _validate_current_token(token: str) -> TokenValidation:
    validation = get_token_store().validate_access_token(token)
    if validation is None:
        raise RuntimeError("MCP bearer token is invalid or expired")
    return validation


@lru_cache(maxsize=1)
def get_app_config() -> AppConfig:
    return load_app_config()


@lru_cache(maxsize=1)
def get_token_store() -> TokenStore:
    config = get_app_config()
    return TokenStore(config.database_url, config.encryption_key)
