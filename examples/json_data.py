# -*- coding: utf-8 -*-
__author__ = 'Most Wanted'


import asyncio
from aiohttp import web


@asyncio.coroutine
def get_json(request):
    data = yield from request.json()
    # Now all is ok when there are no json-data
    return web.Response(body='The response'.encode('utf-8'))


@asyncio.coroutine
def init(loop):
    app = web.Application(loop=loop)
    app.router.add_route('POST', '/', get_json)

    srv = yield from loop.create_server(app.make_handler(),
                                        '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass