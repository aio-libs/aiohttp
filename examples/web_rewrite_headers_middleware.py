#!/usr/bin/env python3
"""
Example for rewriting response headers by middleware.
"""

import asyncio

from aiohttp.web import Application, HTTPException, Response


@asyncio.coroutine
def handler(request):
    return Response(text="Everything is fine")


@asyncio.coroutine
def middleware_factory(app, next_handler):

    @asyncio.coroutine
    def middleware(request):
        try:
            response = yield from next_handler(request)
        except HTTPException as exc:
            response = exc
        if not response.started:
            response.headers['SERVER'] = "Secured Server Software"
        return response

    return middleware


@asyncio.coroutine
def init(loop):
    app = Application(loop=loop, middlewares=[middleware_factory])
    app.router.add_get('/', handler)

    requests_handler = app.make_handler()
    srv = yield from loop.create_server(requests_handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return srv, requests_handler


loop = asyncio.get_event_loop()
srv, requests_handler = loop.run_until_complete(init(loop))
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(requests_handler.finish_connections())
