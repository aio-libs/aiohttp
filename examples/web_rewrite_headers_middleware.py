#!/usr/bin/env python3
"""
Example for rewriting response headers by middleware.
"""

from aiohttp import web


async def handler(request):
    return web.Response(text="Everything is fine")


@web.middleware
async def middleware(request, handler):
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        raise exc
    if not response.prepared:
        response.headers["SERVER"] = "Secured Server Software"
    return response


def init():
    app = web.Application(middlewares=[middleware])
    app.router.add_get("/", handler)
    return app


web.run_app(init())
