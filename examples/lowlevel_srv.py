#!/usr/bin/env python3
"""Example for aiohttp.web low level server."""

import asyncio
import contextlib

from aiohttp import ClientSession, web, web_request


async def handler(request: web_request.BaseRequest) -> web.StreamResponse:
    return web.Response(text="OK")


async def run_test_server() -> tuple[web.Server, asyncio.Server, int]:
    """Start a low-level server on a dynamic port for testing."""
    server = web.Server(handler)
    loop = asyncio.get_running_loop()
    tcp_server = await loop.create_server(server, "localhost", 0)
    assert tcp_server.sockets
    port: int = tcp_server.sockets[0].getsockname()[1]
    return server, tcp_server, port


async def run_tests(port: int) -> None:
    """Run all tests against the server."""
    async with ClientSession() as session:
        async with session.get(f"http://localhost:{port}/") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"
            print("OK: GET / -> 'OK'")

    print("\nAll tests passed!")


async def main() -> None:
    server, tcp_server, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()
        await server.shutdown()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
