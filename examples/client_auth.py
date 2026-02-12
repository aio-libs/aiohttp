#!/usr/bin/env python3
import asyncio

import aiohttp
from aiohttp import BasicAuth, hdrs, web

DEFAULT_URL = "http://httpbin.org/basic-auth/andrew/password"


async def fetch(session: aiohttp.ClientSession, url: str = DEFAULT_URL) -> str:
    print(f"Query {url}")
    async with session.get(url) as resp:
        print(resp.status)
        body = await resp.text()
        print(body)
        return body


async def go(url: str = DEFAULT_URL) -> str:
    async with aiohttp.ClientSession(
        auth=aiohttp.BasicAuth("andrew", "password")
    ) as session:
        return await fetch(session, url)


async def auth_handler(request: web.Request) -> web.Response:
    auth_header = request.headers.get(hdrs.AUTHORIZATION, "")
    if auth_header:
        auth = BasicAuth.decode(auth_header)
        if auth.login == "andrew" and auth.password == "password":
            return web.Response(text="Authenticated")
    return web.Response(status=401, text="Unauthorized")


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start a mock server on a dynamic port for testing."""
    app = web.Application()
    app.router.add_get("/auth", auth_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the mock server."""
    result = await go(f"http://localhost:{port}/auth")
    assert result == "Authenticated"
    print("OK: GET /auth -> Authenticated")
    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
