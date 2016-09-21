#!/usr/bin/env python3
"""Example for aiohttp.web class based views
"""


import asyncio
import functools
import json

from aiohttp.web import Application, Response, View, json_response, run_app


class MyView(View):

    async def get(self):
        return json_response({
            'method': 'get',
            'args': dict(self.request.GET),
            'headers': dict(self.request.headers),
        }, dumps=functools.partial(json.dumps, indent=4))

    async def post(self):
        data = await self.request.post()
        return json_response({
            'method': 'post',
            'args': dict(self.request.GET),
            'data': dict(data),
            'headers': dict(self.request.headers),
        }, dumps=functools.partial(json.dumps, indent=4))


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
    return Response(text=txt, content_type='text/html')


async def init(loop):
    app = Application(loop=loop)
    app.router.add_get('/', index)
    app.router.add_get('/get', MyView)
    app.router.add_post('/post', MyView)
    return app


loop = asyncio.get_event_loop()
app = loop.run_until_complete(init(loop))
run_app(app)
