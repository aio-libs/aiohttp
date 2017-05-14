#!/usr/bin/env python3

import asyncio
import logging

from aiohttp import web


@asyncio.coroutine
def wshandler(request):
    ws = web.WebSocketResponse(autoclose=False)
    ok, protocol = ws.can_start(request)
    if not ok:
        return web.HTTPBadRequest()

    yield from ws.prepare(request)

    while True:
        msg = yield from ws.receive()

        if msg.type == web.WSMsgType.text:
            ws.send_str(msg.data)
        elif msg.type == web.WSMsgType.binary:
            ws.send_bytes(msg.data)
        elif msg.type == web.WSMsgType.close:
            yield from ws.close()
            break
        else:
            break

    return ws


@asyncio.coroutine
def main(loop):
    app = web.Application()
    app.router.add_route('GET', '/', wshandler)

    handler = app.make_handler()
    srv = yield from loop.create_server(handler, '127.0.0.1', 9001)
    print("Server started at http://127.0.0.1:9001")
    return app, srv, handler


@asyncio.coroutine
def finish(app, srv, handler):
    srv.close()
    yield from handler.finish_connections()
    yield from srv.wait_closed()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s')

    loop = asyncio.get_event_loop()
    app, srv, handler = loop.run_until_complete(main(loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(finish(app, srv, handler))
