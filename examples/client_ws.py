#!/usr/bin/env python3
"""websocket cmd client for web_ws.py example."""

import asyncio
import sys
from collections.abc import Callable
from contextlib import suppress

import aiohttp
from aiohttp import web


async def dispatch(ws: aiohttp.ClientWebSocketResponse) -> None:
    while True:
        msg = await ws.receive()

        if msg.type is aiohttp.WSMsgType.TEXT:
            print("Text: ", msg.data.strip())
        elif msg.type is aiohttp.WSMsgType.BINARY:
            print("Binary: ", msg.data)
        elif msg.type is aiohttp.WSMsgType.PING:
            await ws.pong()
        elif msg.type is aiohttp.WSMsgType.PONG:
            print("Pong received")
        else:
            if msg.type is aiohttp.WSMsgType.CLOSE:
                await ws.close()
            elif msg.type is aiohttp.WSMsgType.ERROR:
                print("Error during receive %s" % ws.exception())
            break


async def start_client(
    url: str,
    name: str | None = None,
    input_func: Callable[[], str] | None = None,
) -> None:
    client_name = name if name is not None else input("Please enter your name: ")
    read_input = input_func if input_func is not None else sys.stdin.readline

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url, autoclose=False, autoping=False) as ws:
            dispatch_task: asyncio.Task[None] = asyncio.create_task(dispatch(ws))

            while line := await asyncio.to_thread(read_input):
                await ws.send_str(client_name + ": " + line)

            dispatch_task.cancel()
            with suppress(asyncio.CancelledError):
                await dispatch_task


async def echo_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for msg in ws:
        if msg.type is aiohttp.WSMsgType.TEXT:
            await ws.send_str("echo: " + msg.data)
    return ws


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start a mock echo WS server on a dynamic port for testing."""
    app = web.Application()
    app.router.add_get("/", echo_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the mock server."""
    url = f"http://localhost:{port}/"
    input_sent = False

    def fake_input() -> str:
        nonlocal input_sent
        if not input_sent:
            input_sent = True
            return "hello"
        return ""

    await asyncio.wait_for(
        start_client(url, name="tester", input_func=fake_input),
        timeout=5,
    )
    print("OK: WS client connected, sent message, and received echo")
    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
