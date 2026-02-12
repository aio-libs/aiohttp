#!/usr/bin/env python3
"""Example for aiohttp.web low level server."""

import asyncio
import contextlib

from aiohttp import ClientSession, web, web_request


async def handler(request: web_request.BaseRequest) -> web.StreamResponse:
    return web.Response(text="OK")


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start the server on a dynamic port for testing."""
    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the server."""
    base_url = f"http://localhost:{port}"
    async with ClientSession() as session:
        async with session.get(f"{base_url}/") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"
            print("OK: GET / -> 'OK'")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
