#!/usr/bin/env python3

import asyncio
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

        if msg.type == web.WSMsgType.text:
            await ws.send_str(msg.data)
        elif msg.type == web.WSMsgType.binary:
            await ws.send_bytes(msg.data)
        elif msg.type == web.WSMsgType.close:
            await ws.close()
            break
        else:
            break

    return ws


async def main(loop):
    app = web.Application()
    app.router.add_route("GET", "/", wshandler)

    handler = app._make_handler()
    srv = await loop.create_server(handler, "127.0.0.1", 9001)
    print("Server started at http://127.0.0.1:9001")
    return app, srv, handler


async def finish(app, srv, handler):
    srv.close()
    await handler.shutdown()
    await srv.wait_closed()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s"
    )
    app, srv, handler = loop.run_until_complete(main(loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(finish(app, srv, handler))
