#!/usr/bin/env python3
"""
Example for rewriting response headers by middleware.
"""

import asyncio

from aiohttp.web import Application, HTTPException, Response, run_app


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
        if not response.prepared:
            response.headers['SERVER'] = "Secured Server Software"
        return response

    return middleware


def init(loop):
    app = Application(loop=loop, middlewares=[middleware_factory])
    app.router.add_get('/', handler)
    return app


loop = asyncio.get_event_loop()
app = init(loop)
run_app(app)
