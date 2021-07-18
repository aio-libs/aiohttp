#!/usr/bin/env python3
"""Example of aiohttp.web.Application.on_startup signal handler"""
import asyncio
from typing import List, TypedDict

import aioredis  # type: ignore

from aiohttp import web


class StateDict(TypedDict):
    redis_listener: asyncio.Task[None]
    websockets: List[web.WebSocketResponse]


async def websocket_handler(request: web.Request[StateDict]) -> web.StreamResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    request.app.state["websockets"].append(ws)
    try:
        async for msg in ws:
            print(msg)
            await asyncio.sleep(1)
    finally:
        request.app.state["websockets"].remove(ws)
    return ws


async def on_shutdown(app: web.Application[StateDict]) -> None:
    for ws in app.state["websockets"]:
        await ws.close(code=999, message=b"Server shutdown")


async def listen_to_redis(app: web.Application[StateDict]) -> None:
    try:
        loop = asyncio.get_event_loop()
        sub = await aioredis.create_redis(("localhost", 6379), loop=loop)
        ch, *_ = await sub.subscribe("news")
        async for msg in ch.iter(encoding="utf-8"):
            # Forward message to all connected websockets:
            for ws in app.state["websockets"]:
                await ws.send_str(f"{ch.name}: {msg}")
            print(f"message in {ch.name}: {msg}")
    except asyncio.CancelledError:
        pass
    finally:
        print("Cancel Redis listener: close connection...")
        await sub.unsubscribe(ch.name)
        await sub.quit()
        print("Redis connection closed.")


async def start_background_tasks(app: web.Application[StateDict]) -> None:
    app.state["redis_listener"] = asyncio.create_task(listen_to_redis(app))


async def cleanup_background_tasks(app: web.Application[StateDict]) -> None:
    print("cleanup background tasks...")
    app.state["redis_listener"].cancel()
    await app.state["redis_listener"]


def init() -> web.Application[StateDict]:
    app: web.Application[StateDict] = web.Application()
    app.state["websockets"] = []
    app.router.add_get("/news", websocket_handler)
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    app.on_shutdown.append(on_shutdown)
    return app


web.run_app(init())
