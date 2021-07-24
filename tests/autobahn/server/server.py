#!/usr/bin/env python3

import logging
import sys
from typing import List

from aiohttp import WSCloseCode, web

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


class StateDict(TypedDict):
    websockets: List[web.WebSocketResponse]


async def wshandler(request: web.Request[StateDict]) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(autoclose=False)
    is_ws = ws.can_prepare(request)
    if not is_ws:
        raise web.HTTPBadRequest()

    await ws.prepare(request)

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


async def on_shutdown(app: web.Application[StateDict]) -> None:
    for ws in set(app.state["websockets"]):
        await ws.close(code=WSCloseCode.GOING_AWAY, message=b"Server shutdown")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s"
    )

    app: web.Application[StateDict] = web.Application()
    app.router.add_route("GET", "/", wshandler)
    app.on_shutdown.append(on_shutdown)
    try:
        web.run_app(app, port=9001)
    except KeyboardInterrupt:
        print("Server stopped at http://127.0.0.1:9001")
