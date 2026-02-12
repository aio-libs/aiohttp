#!/usr/bin/env python3
import asyncio
from typing import Any

import aiohttp
from aiohttp import web

DEFAULT_URL = "http://httpbin.org/get"


async def fetch(
    session: aiohttp.ClientSession, url: str = DEFAULT_URL
) -> dict[str, Any]:
    print(f"Query {url}")
    async with session.get(url) as resp:
        print(resp.status)
        data: dict[str, Any] = await resp.json()
        print(data)
        return data


async def go(url: str = DEFAULT_URL) -> dict[str, Any]:
    async with aiohttp.ClientSession() as session:
        return await fetch(session, url)


async def json_handler(request: web.Request) -> web.Response:
    return web.json_response({"url": str(request.url), "method": request.method})


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start a mock server on a dynamic port for testing."""
    app = web.Application()
    app.router.add_get("/get", json_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the mock server."""
    result = await go(f"http://localhost:{port}/get")
    assert result["method"] == "GET"
    print("OK: GET /get -> JSON with method=GET")
    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
