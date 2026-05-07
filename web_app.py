from __future__ import annotations

import contextlib

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

from auth_context import get_app_config, get_token_store
from oauth_server import oauth_routes


def create_web_app(mcp: FastMCP) -> Starlette:
    config = get_app_config()
    store = get_token_store()
    store.init()
    mcp.settings.streamable_http_path = "/"

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=[*oauth_routes(config, store), Mount("/mcp", app=mcp.streamable_http_app())],
        lifespan=lifespan,
    )


def run_web_app(mcp: FastMCP) -> None:
    import uvicorn

    config = get_app_config()
    uvicorn.run(create_web_app(mcp), host=config.server.host, port=config.server.port)
