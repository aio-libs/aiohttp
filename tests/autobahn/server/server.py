#!/usr/bin/env python3

import logging

from aiohttp import WSCloseCode, web


async def wshandler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(autoclose=False)
    is_ws = ws.can_prepare(request)
    if not is_ws:
        raise web.HTTPBadRequest()

    await ws.prepare(request)

    request.app["websockets"].append(ws)

    while True:
        msg = await ws.receive()

        if msg.type == web.WSMsgType.TEXT:
            await ws.send_str(msg.data)
        elif msg.type == web.WSMsgType.BINARY:
            await ws.send_bytes(msg.data)
        elif msg.type == web.WSMsgType.CLOSE:
            await ws.close()
            break
        else:
            break

    return ws


async def on_shutdown(app: web.Application) -> None:
    for ws in set(app["websockets"]):
        await ws.close(code=WSCloseCode.GOING_AWAY, message="Server shutdown")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s"
    )

    app = web.Application()
    app["websockets"] = []
    app.router.add_route("GET", "/", wshandler)
    app.on_shutdown.append(on_shutdown)
    try:
        web.run_app(app, port=9001)
    except KeyboardInterrupt:
        print("Server stopped at http://127.0.0.1:9001")
