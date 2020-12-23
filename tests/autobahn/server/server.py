#!/usr/bin/env python3

import logging

from aiohttp import web


async def wshandler(request):
    ws = web.WebSocketResponse(autoclose=False)
    is_ws = ws.can_prepare(request)
    if not is_ws:
        return web.HTTPBadRequest()

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


def main():
    app = web.Application()
    app.router.add_route("GET", "/", wshandler)

    web.run_app(app, port=9001)
    print("Server started at http://0.0.0.0:9001")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s"
    )
    main()
