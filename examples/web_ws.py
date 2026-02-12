#!/usr/bin/env python3
"""Example for aiohttp.web websocket server."""

# The extra strict mypy settings are here to help test that `Application[AppKey()]`
# syntax is working correctly. A regression will cause mypy to raise an error.
# mypy: disallow-any-expr, disallow-any-unimported, disallow-subclassing-any

import asyncio
import os

from aiohttp import ClientSession, web

WS_FILE = os.path.join(os.path.dirname(__file__), "websocket.html")
sockets = web.AppKey("sockets", list[web.WebSocketResponse])


async def wshandler(request: web.Request) -> web.WebSocketResponse | web.Response:
    resp = web.WebSocketResponse()
    available = resp.can_prepare(request)
    if not available:
        with open(WS_FILE, "rb") as fp:
            return web.Response(body=fp.read(), content_type="text/html")

    await resp.prepare(request)

    await resp.send_str("Welcome!!!")

    try:
        print("Someone joined.")
        for ws in request.app[sockets]:
            await ws.send_str("Someone joined")
        request.app[sockets].append(resp)

        async for msg in resp:
            if msg.type is web.WSMsgType.TEXT:
                for ws in request.app[sockets]:
                    if ws is not resp:
                        await ws.send_str(msg.data)
            else:
                return resp
        return resp

    finally:
        request.app[sockets].remove(resp)
        print("Someone disconnected.")
        for ws in request.app[sockets]:
            await ws.send_str("Someone disconnected.")


async def on_shutdown(app: web.Application) -> None:
    for ws in app[sockets]:
        await ws.close()


def init() -> web.Application:
    app = web.Application()
    l: list[web.WebSocketResponse] = []
    app[sockets] = l
    app.router.add_get("/", wshandler)
    app.on_shutdown.append(on_shutdown)
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
    url = f"ws://localhost:{port}/"
    async with ClientSession() as session:
        async with session.ws_connect(url) as ws1:
            msg = await ws1.receive_str()
            assert msg == "Welcome!!!"
            print("OK: WS client 1 -> Welcome!!!")

            async with session.ws_connect(url) as ws2:
                msg = await ws2.receive_str()
                assert msg == "Welcome!!!"

                msg = await ws1.receive_str()
                assert msg == "Someone joined"
                print("OK: Client 1 notified of join")

                await ws1.send_str("Hello")
                msg = await ws2.receive_str()
                assert msg == "Hello"
                print("OK: Message broadcast from client 1 to client 2")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
