#!/usr/bin/env python3
"""Example for aiohttp.web websocket server."""

# The extra strict mypy settings are here to help test that `Application[AppKey()]`
# syntax is working correctly. A regression will cause mypy to raise an error.
# mypy: disallow-any-expr, disallow-any-unimported, disallow-subclassing-any

import os
from typing import List, Union

from aiohttp import web

WS_FILE = os.path.join(os.path.dirname(__file__), "websocket.html")
sockets = web.AppKey("sockets", List[web.WebSocketResponse])


async def wshandler(request: web.Request) -> Union[web.WebSocketResponse, web.Response]:
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

        async for msg in resp:  # type: ignore[misc]
            if msg.type == web.WSMsgType.TEXT:  # type: ignore[misc]
                for ws in request.app[sockets]:
                    if ws is not resp:
                        await ws.send_str(msg.data)  # type: ignore[misc]
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
    l: List[web.WebSocketResponse] = []
    app[sockets] = l
    app.router.add_get("/", wshandler)
    app.on_shutdown.append(on_shutdown)
    return app


web.run_app(init())
