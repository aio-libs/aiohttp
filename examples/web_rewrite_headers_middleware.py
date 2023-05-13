#!/usr/bin/env python3
"""Example for rewriting response headers by middleware."""

from aiohttp import web
from aiohttp.typedefs import Handler


async def handler(request: web.Request) -> web.StreamResponse:
    return web.Response(text="Everything is fine")


async def middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        raise exc
    if not response.prepared:
        response.headers["SERVER"] = "Secured Server Software"
    return response


def init() -> web.Application:
    app = web.Application(middlewares=[middleware])
    app.router.add_get("/", handler)
    return app


web.run_app(init())
