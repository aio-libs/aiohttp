#!/usr/bin/env python3
"""Example for rewriting response headers by middleware."""

import asyncio

from aiohttp import ClientSession, web
from aiohttp.typedefs import Handler


async def handler(request: web.Request) -> web.StreamResponse:
    return web.Response(text="Everything is fine")


async def middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        raise exc
    if not response.prepared:
        response.headers["SERVER"] = "Secured Server Software"
    return response


def init() -> web.Application:
    app = web.Application(middlewares=[middleware])
    app.router.add_get("/", handler)
    return app


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start the server on a dynamic port for testing."""
    runner = web.AppRunner(init())
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
            assert resp.headers.get("SERVER") == "Secured Server Software"
            text = await resp.text()
            assert text == "Everything is fine"
            print("OK: GET / -> 200 with rewritten SERVER header")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
