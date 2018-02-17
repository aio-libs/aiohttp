#!/usr/bin/env python3
"""
Example for rewriting response headers by middleware.
"""

from aiohttp.web import Application, HTTPException, Response, run_app


async def handler(request):
    return Response(text="Everything is fine")


async def middleware_factory(app, next_handler):

    async def middleware(request):
        try:
            response = await next_handler(request)
        except HTTPException as exc:
            response = exc
        if not response.prepared:
            response.headers['SERVER'] = "Secured Server Software"
        return response

    return middleware


def init():
    app = Application(loop=loop, middlewares=[middleware_factory])
    app.router.add_get('/', handler)
    return app


run_app(init())
