#!/usr/bin/env python3
"""Example for aiohttp.web class based views."""

import functools
import json

from aiohttp import web


class MyView(web.View):
    async def get(self) -> web.StreamResponse:
        return web.json_response(
            {
                "method": self.request.method,
                "args": dict(self.request.rel_url.query),
                "headers": dict(self.request.headers),
            },
            dumps=functools.partial(json.dumps, indent=4),
        )

    async def post(self) -> web.StreamResponse:
        data = await self.request.post()
        return web.json_response(
            {
                "method": self.request.method,
                "data": dict(data),
                "headers": dict(self.request.headers),
            },
            dumps=functools.partial(json.dumps, indent=4),
        )


async def index(request: web.Request) -> web.StreamResponse:
    txt = """
      <html>
        <head>
          <title>Class based view example</title>
        </head>
        <body>
          <h1>Class based view example</h1>
          <ul>
            <li><a href="/">/</a> This page
            <li><a href="/get">/get</a> Returns GET data.
            <li><a href="/post">/post</a> Returns POST data.
          </ul>
        </body>
      </html>
    """
    return web.Response(text=txt, content_type="text/html")


def init() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/get", MyView)
    app.router.add_post("/post", MyView)
    return app


web.run_app(init())
