from __future__ import annotations

import contextlib
import logging
import sys

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

from auth_context import get_app_config, get_token_store
from oauth_server import oauth_routes


def create_web_app(mcp: FastMCP) -> Starlette:
    config = get_app_config()
    store = get_token_store()
    store.init()

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=[*oauth_routes(config, store), Mount("/", app=mcp.streamable_http_app())],
        lifespan=lifespan,
    )


def run_web_app(mcp: FastMCP) -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stdout,
        force=True,
    )

    config = get_app_config()
    uvicorn.run(
        create_web_app(mcp),
        host=config.server.host,
        port=config.server.port,
        log_config=None,
    )
