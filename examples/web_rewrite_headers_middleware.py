#!/usr/bin/env python3
"""
Example for rewriting response headers by middleware.
"""

from aiohttp import web


async def handler(request):
    return web.Response(text="Everything is fine")


async def middleware_factory(app, next_handler):

    async def middleware(request):
        try:
            response = await next_handler(request)
        except web.HTTPException as exc:
            raise exc
        if not response.prepared:
            response.headers['SERVER'] = "Secured Server Software"
        return response

    return middleware


def init():
    app = web.Application(middlewares=[middleware_factory])
    app.router.add_get('/', handler)
    return app


web.run_app(init())
