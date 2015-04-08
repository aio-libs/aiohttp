#!/usr/bin/env python3
"""Example for aiohttp.web websocket server
"""

import asyncio
import os
from aiohttp.web import Application, Response, MsgType, WebSocketResponse

WS_FILE = os.path.join(os.path.dirname(__file__), 'websocket.html')


@asyncio.coroutine
def wshandler(request):
    resp = WebSocketResponse()
    ok, protocol = resp.can_start(request)
    if not ok:
        with open(WS_FILE, 'rb') as fp:
            return Response(body=fp.read(), content_type='text/html')

    resp.start(request)
    print('Someone joined.')
    for ws in request.app['sockets']:
        ws.send_str('Someone joined')
    request.app['sockets'].append(resp)

    while True:
        msg = yield from resp.receive()

        if msg.tp == MsgType.text:
            for ws in request.app['sockets']:
                if ws is not resp:
                    ws.send_str(msg.data)
        else:
            break

    request.app['sockets'].remove(resp)
    print('Someone disconnected.')
    for ws in request.app['sockets']:
        ws.send_str('Someone disconnected.')
    return resp


@asyncio.coroutine
def init(loop):
    app = Application(loop=loop)
    app['sockets'] = []
    app.router.add_route('GET', '/', wshandler)

    handler = app.make_handler()
    srv = yield from loop.create_server(handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return app, srv, handler


@asyncio.coroutine
def finish(app, srv, handler):
    for ws in app['sockets']:
        ws.close()
    app['sockets'].clear()
    yield from asyncio.sleep(0.1)
    srv.close()
    yield from handler.finish_connections()
    yield from srv.wait_closed()


loop = asyncio.get_event_loop()
app, srv, handler = loop.run_until_complete(init(loop))
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(finish(app, srv, handler))
