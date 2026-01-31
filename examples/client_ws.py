#!/usr/bin/env python3
"""websocket cmd client for web_ws.py example."""

import argparse
import asyncio
import sys
from collections.abc import Callable
from contextlib import suppress

import aiohttp


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


ARGS = argparse.ArgumentParser(
    description="websocket console client for wssrv.py example."
)
ARGS.add_argument(
    "--host", action="store", dest="host", default="127.0.0.1", help="Host name"
)
ARGS.add_argument(
    "--port", action="store", dest="port", default=8080, type=int, help="Port number"
)

if __name__ == "__main__":
    args = ARGS.parse_args()
    if ":" in args.host:
        args.host, port = args.host.split(":", 1)
        args.port = int(port)

    url = f"http://{args.host}:{args.port}"

    asyncio.run(start_client(url))
