#!/usr/bin/env python3

import logging

from aiohttp import WSCloseCode, web

websockets = web.AppKey("websockets", list[web.WebSocketResponse])


async def wshandler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(autoclose=False)
    await ws.prepare(request)

    request.app[websockets].append(ws)

    async for msg in ws:
        if msg.type is web.WSMsgType.TEXT:
            await ws.send_str(msg.data)
        elif msg.type is web.WSMsgType.BINARY:
            await ws.send_bytes(msg.data)
        else:
            break

    return ws


async def on_shutdown(app: web.Application) -> None:
    for ws in app[websockets]:
        await ws.close(code=WSCloseCode.GOING_AWAY, message=b"Server shutdown")


if __name__ == "__main__":  # pragma: no branch
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s"
    )

    app = web.Application()
    app[websockets] = []
    app.router.add_route("GET", "/", wshandler)
    app.on_shutdown.append(on_shutdown)
    web.run_app(app, port=9001)
