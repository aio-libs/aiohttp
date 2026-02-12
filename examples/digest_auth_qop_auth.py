#!/usr/bin/env python3
"""
Example of using digest authentication middleware with aiohttp client.

This example shows how to use the DigestAuthMiddleware from
aiohttp.client_middleware_digest_auth to authenticate with a server
that requires digest authentication with different qop options.

It uses a local mock server instead of an external service,
testing multiple qop and algorithm combinations.
"""

import asyncio
from collections.abc import Awaitable, Callable
from itertools import product

from aiohttp import ClientSession, web
from aiohttp.client_middleware_digest_auth import DigestAuthMiddleware

QOP_OPTIONS = ["auth", "auth-int"]
ALGORITHMS = ["MD5", "SHA-256", "SHA-512"]
TEST_COMBINATIONS = list(product(QOP_OPTIONS, ALGORITHMS))

USERNAME = "testuser"
PASSWORD = "testpass"


def _make_challenge_response(qop: str, algorithm: str) -> web.Response:
    """Build a 401 response with a Digest WWW-Authenticate challenge."""
    nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    challenge = (
        f'Digest realm="testrealm", '
        f'nonce="{nonce}", '
        f'qop="{qop}", '
        f"algorithm={algorithm}"
    )
    return web.Response(status=401, headers={"WWW-Authenticate": challenge})


def _make_digest_handler(
    qop: str, algorithm: str
) -> Callable[[web.Request], Awaitable[web.Response]]:
    """Create a handler that challenges with specific qop and algorithm."""

    async def handler(request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Digest"):
            return _make_challenge_response(qop, algorithm)
        return web.json_response({"authenticated": True, "user": USERNAME, "qop": qop})

    return handler


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start a mock digest auth server on a dynamic port."""
    app = web.Application()
    for qop, algorithm in TEST_COMBINATIONS:
        path = f"/digest-auth/{qop}/{algorithm}"
        app.router.add_get(path, _make_digest_handler(qop, algorithm))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Test digest authentication with multiple qop/algorithm combinations."""
    base_url = f"http://localhost:{port}"
    digest_auth = DigestAuthMiddleware(login=USERNAME, password=PASSWORD)

    async with ClientSession(middlewares=(digest_auth,)) as session:
        for qop, algorithm in TEST_COMBINATIONS:
            url = f"{base_url}/digest-auth/{qop}/{algorithm}"
            print(f"\n=== Testing qop={qop}, algorithm={algorithm} ===")
            async with session.get(url) as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["authenticated"] is True
                print(f"OK: Authenticated with qop={qop}, algorithm={algorithm}")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
