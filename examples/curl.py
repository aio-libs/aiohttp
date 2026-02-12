#!/usr/bin/env python3
"""Simple HTTP GET client with CLI support."""

import argparse
import asyncio

import aiohttp
from aiohttp import web


async def curl(url: str) -> str:
    """GET a URL and return its content."""
    async with aiohttp.ClientSession() as session:
        async with session.request("GET", url) as response:
            print(repr(response))
            chunk = await response.content.read()
            print("Downloaded: %s" % len(chunk))
            return chunk.decode()


async def mock_handler(request: web.Request) -> web.Response:
    return web.Response(text="Hello from mock server")


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start a mock server on a dynamic port for testing."""
    app = web.Application()
    app.router.add_get("/", mock_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the mock server."""
    result = await curl(f"http://localhost:{port}/")
    assert result == "Hello from mock server"
    print("OK: curl / -> 'Hello from mock server'")
    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GET url example")
    parser.add_argument("url", nargs="?", metavar="URL", help="URL to download")
    options = parser.parse_args()

    if options.url:
        asyncio.run(curl(options.url))
    else:
        asyncio.run(main())
