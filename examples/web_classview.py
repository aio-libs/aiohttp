#!/usr/bin/env python3
"""Example for aiohttp.web class based views."""


import functools
import json

from aiohttp import web


class MyView(web.View):
    async def get(self):
        return web.json_response(
            {
                "method": "get",
                "args": dict(self.request.query),
                "headers": dict(self.request.headers),
            },
            dumps=functools.partial(json.dumps, indent=4),
        )

    async def post(self):
        data = await self.request.post()
        return web.json_response(
            {
                "method": "post",
                "args": dict(self.request.query),
                "data": dict(data),
                "headers": dict(self.request.headers),
            },
            dumps=functools.partial(json.dumps, indent=4),
        )


async def index(request):
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


def init():
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/get", MyView)
    app.router.add_post("/post", MyView)
    return app


web.run_app(init())
