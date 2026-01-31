#!/usr/bin/env python3
"""Example of aiohttp.web.Application.on_startup signal handler"""
import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

import valkey.asyncio as valkey

from aiohttp import web

valkey_listener = web.AppKey("valkey_listener", asyncio.Task[None])
websockets = web.AppKey("websockets", list[web.WebSocketResponse])
skip_valkey_key = web.AppKey("skip_valkey", bool)


async def websocket_handler(request: web.Request) -> web.StreamResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    request.app[websockets].append(ws)
    try:
        async for msg in ws:
            print(msg)
            await asyncio.sleep(1)
    finally:
        request.app[websockets].remove(ws)
    return ws


async def on_shutdown(app: web.Application) -> None:
    for ws in app[websockets]:
        await ws.close(code=999, message=b"Server shutdown")


async def listen_to_valkey(app: web.Application) -> None:
    r = valkey.Valkey(host="localhost", port=6379, decode_responses=True)
    channel = "news"
    async with r.pubsub() as sub:
        await sub.subscribe(channel)
        async for msg in sub.listen():
            if msg["type"] != "message":
                continue
            for ws in app[websockets]:
                await ws.send_str(f"{channel}: {msg}")
            print(f"message in {channel}: {msg}")


@asynccontextmanager
async def background_tasks(app: web.Application) -> AsyncIterator[None]:
    if app.get(skip_valkey_key, False):
        yield
        return

    app[valkey_listener] = asyncio.create_task(listen_to_valkey(app))
    yield
    print("cleanup background tasks...")
    app[valkey_listener].cancel()
    with suppress(asyncio.CancelledError):
        await app[valkey_listener]


def init(skip_valkey: bool = False) -> web.Application:
    app = web.Application()
    app[websockets] = []
    app[skip_valkey_key] = skip_valkey
    app.router.add_get("/news", websocket_handler)
    app.cleanup_ctx.append(background_tasks)
    app.on_shutdown.append(on_shutdown)
    return app


if __name__ == "__main__":
    web.run_app(init())
