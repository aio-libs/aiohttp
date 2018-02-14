#!/usr/bin/env python3
"""Example for aiohttp.web websocket server
"""

import os

from aiohttp.web import (Application, Response, WebSocketResponse, WSMsgType,
                         run_app)


WS_FILE = os.path.join(os.path.dirname(__file__), 'websocket.html')


async def wshandler(request):
    resp = WebSocketResponse()
    available = resp.can_prepare(request)
    if not available:
        with open(WS_FILE, 'rb') as fp:
            return Response(body=fp.read(), content_type='text/html')

    await resp.prepare(request)

    try:
        print('Someone joined.')
        for ws in request.app['sockets']:
            await ws.send_str('Someone joined')
        request.app['sockets'].append(resp)

        async for msg in resp:
            if msg.type == WSMsgType.TEXT:
                for ws in request.app['sockets']:
                    if ws is not resp:
                        await ws.send_str(msg.data)
            else:
                return resp
        return resp

    finally:
        request.app['sockets'].remove(resp)
        print('Someone disconnected.')
        for ws in request.app['sockets']:
            await ws.send_str('Someone disconnected.')


async def on_shutdown(app):
    for ws in app['sockets']:
        await ws.close()


def init():
    app = Application()
    app['sockets'] = []
    app.router.add_get('/', wshandler)
    app.on_shutdown.append(on_shutdown)
    return app


run_app(init())
