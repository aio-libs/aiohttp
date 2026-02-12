#!/usr/bin/env python3
"""
Example of using digest authentication middleware with aiohttp client.

This example shows how to use the DigestAuthMiddleware from
aiohttp.client_middleware_digest_auth to authenticate with a server
that requires digest authentication with qop="auth".
"""

import asyncio

from aiohttp import ClientSession, web
from aiohttp.client_middleware_digest_auth import DigestAuthMiddleware

USERNAME = "testuser"
PASSWORD = "testpass"


async def digest_auth_handler(request: web.Request) -> web.Response:
    """Mock digest auth endpoint."""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header or not auth_header.startswith("Digest"):
        # Challenge with digest auth
        return web.Response(
            status=401,
            headers={
                "WWW-Authenticate": (
                    f'Digest realm="testrealm", '
                    f'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
                    f'qop="auth", '
                    f"algorithm=MD5"
                )
            },
        )

    # Authenticated successfully
    return web.json_response({"authenticated": True, "user": USERNAME, "qop": "auth"})


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start a mock digest auth server on a dynamic port."""
    app = web.Application()
    app.router.add_get("/digest-auth", digest_auth_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Test digest authentication with qop='auth'."""
    base_url = f"http://localhost:{port}"
    digest_auth = DigestAuthMiddleware(login=USERNAME, password=PASSWORD)

    async with ClientSession(middlewares=(digest_auth,)) as session:
        async with session.get(f"{base_url}/digest-auth") as resp:
            assert resp.status == 200
            json_response = await resp.json()
            assert json_response["authenticated"] is True
            assert json_response["user"] == USERNAME
            print(f"OK: Digest auth with qop=auth -> {json_response}")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
