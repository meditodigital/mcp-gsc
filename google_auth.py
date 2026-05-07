from __future__ import annotations

import base64
import hashlib
import os
import secrets

from google.auth.transport.requests import Request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from app_config import AppConfig
from token_store import Principal, TokenStore


class GoogleAuthError(ValueError):
    pass


def start_google_login(config: AppConfig, store: TokenStore, return_to: str) -> str:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _s256(code_verifier)
    store.create_google_flow(state, code_verifier, nonce, return_to, 600)
    flow = _flow(config)
    url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        nonce=nonce,
        hd=config.google.hosted_domain,
    )
    return url


def complete_google_login(config: AppConfig, store: TokenStore, state: str | None, code: str | None) -> tuple[Principal, str]:
    if state is None or code is None:
        raise GoogleAuthError("Google callback is missing state or code")
    auth_flow = store.consume_google_flow(state)
    if auth_flow is None:
        raise GoogleAuthError("Google login state is missing or expired")

    flow = _flow(config)
    os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")
    try:
        flow.fetch_token(code=code, code_verifier=auth_flow.code_verifier)
    except Exception as error:
        raise GoogleAuthError("Google token exchange failed") from error
    credentials = flow.credentials
    if not credentials.id_token:
        raise GoogleAuthError("Google did not return an identity token")
    claims = id_token.verify_oauth2_token(credentials.id_token, Request(), config.google.client_id)
    if claims.get("nonce") != auth_flow.nonce:
        raise GoogleAuthError("Google login nonce did not match")
    if claims.get("email_verified") is not True:
        raise GoogleAuthError("Google account email is not verified")
    if claims.get("hd") != config.google.hosted_domain:
        raise GoogleAuthError("Google account is outside the configured Workspace")
    if not isinstance(claims.get("sub"), str) or not isinstance(claims.get("email"), str):
        raise GoogleAuthError("Google identity token is missing required profile fields")
    if not credentials.refresh_token:
        raise GoogleAuthError("Google did not return a refresh token")

    principal = Principal(
        subject=claims["sub"],
        email=claims["email"],
        hosted_domain=claims["hd"],
        display_name=claims.get("name") if isinstance(claims.get("name"), str) else None,
    )
    store.store_google_credentials(principal, credentials.to_json(), list(credentials.granted_scopes or config.google.scopes))
    return principal, auth_flow.return_to


def google_callback_url(config: AppConfig) -> str:
    return f"{config.server.public_base_url}/auth/google/callback"


def _flow(config: AppConfig) -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": config.google.client_id,
                "client_secret": config.google.client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [google_callback_url(config)],
            }
        },
        scopes=config.google.scopes,
        redirect_uri=google_callback_url(config),
    )


def _s256(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
