from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import parse_qs, urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from app_config import AppConfig
from google_auth import GoogleAuthError, complete_google_login, start_google_login
from token_store import Principal, TokenStore


def oauth_routes(config: AppConfig, store: TokenStore) -> list[Route]:
    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def ready(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def google_start(request: Request) -> Response:
        return RedirectResponse(start_google_login(config, store, _relative_next(request)), 302)

    async def google_callback(request: Request) -> Response:
        try:
            principal, return_to = complete_google_login(
                config,
                store,
                request.query_params.get("state"),
                request.query_params.get("code"),
            )
        except GoogleAuthError as error:
            return JSONResponse({"error": "invalid_google_login", "error_description": str(error)}, 401)
        response = RedirectResponse(return_to, 303)
        _set_session_cookie(response, config, principal)
        return response

    async def authorize(request: Request) -> Response:
        principal = _read_session_cookie(request, config)
        if principal is None:
            return RedirectResponse(start_google_login(config, store, _relative_url(request)), 303)
        error = _validate_authorize_request(request, config)
        if error is not None:
            return _oauth_error(*error)
        scopes = _oauth_scopes(request.query_params.get("scope"))
        code = secrets.token_urlsafe(48)
        store.create_authorization_code(
            code=code,
            client_id=config.oauth.client_id,
            redirect_uri=request.query_params["redirect_uri"],
            code_challenge=request.query_params["code_challenge"],
            scopes=scopes,
            principal=principal,
            ttl_seconds=config.oauth.authorization_code_ttl_seconds,
        )
        redirect = request.query_params["redirect_uri"]
        params = {"code": code}
        if request.query_params.get("state"):
            params["state"] = request.query_params["state"]
        separator = "&" if "?" in redirect else "?"
        return RedirectResponse(f"{redirect}{separator}{urlencode(params)}", 302)

    async def token(request: Request) -> Response:
        body = await _form_body(request)
        credentials = _client_credentials(request, body)
        if not _valid_client(config, credentials.get("client_id"), credentials.get("client_secret")):
            return _oauth_error("invalid_client", "Invalid OAuth client credentials", 401, basic=True)
        grant_type = body.get("grant_type")
        if grant_type == "authorization_code":
            return _authorization_code_token(config, store, body)
        if grant_type == "refresh_token":
            return _refresh_token(config, store, body)
        return _oauth_error("unsupported_grant_type", "Unsupported grant_type", 400)

    async def revoke(request: Request) -> Response:
        body = await _form_body(request)
        credentials = _client_credentials(request, body)
        if not _valid_client(config, credentials.get("client_id"), credentials.get("client_secret")):
            return _oauth_error("invalid_client", "Invalid OAuth client credentials", 401, basic=True)
        token_value = body.get("token")
        if token_value:
            store.revoke_token(token_value, config.oauth.client_id)
        return JSONResponse({})

    async def protected_resource(request: Request) -> Response:
        return JSONResponse(_protected_resource_metadata(config, "/"))

    async def protected_mcp_resource(request: Request) -> Response:
        return JSONResponse(_protected_resource_metadata(config, "/mcp"))

    async def authorization_server(request: Request) -> Response:
        return JSONResponse(_authorization_server_metadata(config))

    return [
        Route("/health", health, methods=["GET"]),
        Route("/ready", ready, methods=["GET"]),
        Route("/auth/google/start", google_start, methods=["GET"]),
        Route("/auth/google/callback", google_callback, methods=["GET"]),
        Route("/oauth/authorize", authorize, methods=["GET"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/oauth/token", token, methods=["POST"]),
        Route("/oauth/revoke", revoke, methods=["POST"]),
        Route("/.well-known/oauth-protected-resource", protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", protected_mcp_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", authorization_server, methods=["GET"]),
    ]


def _authorization_code_token(config: AppConfig, store: TokenStore, body: dict[str, str]) -> Response:
    code = body.get("code")
    redirect_uri = body.get("redirect_uri")
    verifier = body.get("code_verifier")
    if not code or not redirect_uri or not verifier:
        return _oauth_error("invalid_request", "Missing authorization code grant field", 400)
    record = store.consume_authorization_code(code, config.oauth.client_id, redirect_uri)
    if record is None or not _verify_s256(record.code_challenge, verifier):
        return _oauth_error("invalid_grant", "Invalid authorization code", 400)
    pair = store.create_token_pair(
        config.oauth.client_id,
        record.principal,
        record.scopes,
        config.oauth.access_token_ttl_seconds,
        config.oauth.refresh_token_ttl_seconds,
    )
    return JSONResponse(_token_response(pair.access_token, pair.refresh_token, config.oauth.access_token_ttl_seconds, record.scopes))


def _refresh_token(config: AppConfig, store: TokenStore, body: dict[str, str]) -> Response:
    refresh_token = body.get("refresh_token")
    if not refresh_token:
        return _oauth_error("invalid_request", "Missing refresh_token", 400)
    rotated = store.rotate_refresh_token(
        refresh_token,
        config.oauth.client_id,
        config.oauth.access_token_ttl_seconds,
        config.oauth.refresh_token_ttl_seconds,
    )
    if rotated is None:
        return _oauth_error("invalid_grant", "Invalid refresh token", 400)
    pair, validation = rotated
    return JSONResponse(_token_response(pair.access_token, pair.refresh_token, config.oauth.access_token_ttl_seconds, validation.scopes))


def _token_response(access_token: str, refresh_token: str, expires_in: int, scopes: list[str]) -> dict[str, object]:
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": refresh_token,
        "scope": " ".join(scopes),
    }


def _validate_authorize_request(request: Request, config: AppConfig) -> tuple[str, str, int] | None:
    if request.query_params.get("response_type") != "code":
        return "invalid_request", "response_type must be code", 400
    if request.query_params.get("client_id") != config.oauth.client_id:
        return "invalid_client", "Unknown OAuth client", 401
    if request.query_params.get("redirect_uri") not in config.oauth.redirect_uris:
        return "invalid_request", "Invalid redirect_uri", 400
    if request.query_params.get("code_challenge_method") != "S256":
        return "invalid_request", "code_challenge_method must be S256", 400
    if not request.query_params.get("code_challenge"):
        return "invalid_request", "Missing code_challenge", 400
    unsupported = [scope for scope in _oauth_scopes(request.query_params.get("scope")) if scope != "mcp"]
    if unsupported:
        return "invalid_scope", "Unsupported scope", 400
    return None


def _oauth_scopes(scope: str | None) -> list[str]:
    scopes = [item for item in (scope or "mcp").split() if item]
    return scopes or ["mcp"]


async def _form_body(request: Request) -> dict[str, str]:
    parsed = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items() if values}


def _client_credentials(request: Request, body: dict[str, str]) -> dict[str, str | None]:
    header = request.headers.get("authorization")
    if header and header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header.removeprefix("Basic ")).decode("utf-8")
        except Exception:
            return {"client_id": None, "client_secret": None}
        if ":" in decoded:
            client_id, client_secret = decoded.split(":", 1)
            return {"client_id": client_id, "client_secret": client_secret}
    return {"client_id": body.get("client_id"), "client_secret": body.get("client_secret")}


def _valid_client(config: AppConfig, client_id: str | None, client_secret: str | None) -> bool:
    return client_id == config.oauth.client_id and client_secret is not None and hmac.compare_digest(client_secret, config.oauth.client_secret)


def _oauth_error(code: str, description: str, status: int, basic: bool = False) -> JSONResponse:
    response = JSONResponse({"error": code, "error_description": description}, status)
    if basic:
        response.headers["www-authenticate"] = 'Basic realm="mcp-gsc"'
    return response


def _relative_next(request: Request) -> str:
    value = request.query_params.get("next") or "/"
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


def _relative_url(request: Request) -> str:
    return f"{request.url.path}?{request.url.query}" if request.url.query else request.url.path


def _set_session_cookie(response: Response, config: AppConfig, principal: Principal) -> None:
    payload = {
        "sub": principal.subject,
        "email": principal.email,
        "hd": principal.hosted_domain,
        "name": principal.display_name,
        "exp": int(time.time()) + config.session.ttl_seconds,
    }
    response.set_cookie(
        config.session.cookie_name,
        _sign(payload, config.session.cookie_secret),
        max_age=config.session.ttl_seconds,
        httponly=True,
        secure=config.session.secure,
        samesite="lax",
    )


def _read_session_cookie(request: Request, config: AppConfig) -> Principal | None:
    payload = _unsign(request.cookies.get(config.session.cookie_name), config.session.cookie_secret)
    if payload is None or int(payload.get("exp", 0)) <= int(time.time()):
        return None
    if payload.get("hd") != config.google.hosted_domain:
        return None
    return Principal(
        subject=str(payload.get("sub")),
        email=str(payload.get("email")),
        hosted_domain=str(payload.get("hd")),
        display_name=payload.get("name") if isinstance(payload.get("name"), str) else None,
    )


def _sign(payload: dict[str, object], secret: str) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{signature}"


def _unsign(value: str | None, secret: str) -> dict[str, object] | None:
    if value is None or "." not in value:
        return None
    body, signature = value.split(".", 1)
    expected = _b64(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        return json.loads(_unb64(body))
    except Exception:
        return None


def _verify_s256(challenge: str, verifier: str) -> bool:
    return hmac.compare_digest(challenge, _s256(verifier))


def _s256(value: str) -> str:
    return _b64(hashlib.sha256(value.encode("ascii")).digest())


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _protected_resource_metadata(config: AppConfig, path: str) -> dict[str, object]:
    return {
        "resource": f"{config.server.public_base_url}{path}",
        "authorization_servers": [config.server.public_base_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    }


def _authorization_server_metadata(config: AppConfig) -> dict[str, object]:
    return {
        "issuer": config.server.public_base_url,
        "authorization_endpoint": f"{config.server.public_base_url}/oauth/authorize",
        "token_endpoint": f"{config.server.public_base_url}/oauth/token",
        "revocation_endpoint": f"{config.server.public_base_url}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["mcp"],
    }
