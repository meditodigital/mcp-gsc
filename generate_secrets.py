from __future__ import annotations

import base64
import os
import secrets


def main() -> None:
    values = {
        "APP_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
        "SESSION_COOKIE_SECRET": secrets.token_urlsafe(48),
        "MCP_OAUTH_CLIENT_ID": f"mcp-{secrets.token_urlsafe(18)}",
        "MCP_OAUTH_CLIENT_SECRET": secrets.token_urlsafe(48),
    }
    for key, value in values.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
