#!/usr/bin/env python3
"""Example of aiohttp.web.Application.on_startup signal handler"""
import asyncio
from typing import List

import aioredis

from aiohttp import web

redis_listener = web.AppKey("redis_listener", asyncio.Task[None])
websockets = web.AppKey("websockets", List[web.WebSocketResponse])


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


async def listen_to_redis(app: web.Application) -> None:
    sub = await aioredis.Redis(host="localhost", port=6379)
    ch, *_ = await sub.subscribe("news")
    try:
        async for msg in ch.iter(encoding="utf-8"):
            # Forward message to all connected websockets:
            for ws in app[websockets]:
                await ws.send_str(f"{ch.name}: {msg}")
            print(f"message in {ch.name}: {msg}")
    except asyncio.CancelledError:
        pass
    finally:
        print("Cancel Redis listener: close connection...")
        await sub.unsubscribe(ch.name)
        await sub.quit()
        print("Redis connection closed.")


async def start_background_tasks(app: web.Application) -> None:
    app[redis_listener] = asyncio.create_task(listen_to_redis(app))


async def cleanup_background_tasks(app: web.Application) -> None:
    print("cleanup background tasks...")
    app[redis_listener].cancel()
    await app[redis_listener]


def init() -> web.Application:
    app = web.Application()
    l: List[web.WebSocketResponse] = []
    app[websockets] = l
    app.router.add_get("/news", websocket_handler)
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    app.on_shutdown.append(on_shutdown)
    return app


web.run_app(init())
