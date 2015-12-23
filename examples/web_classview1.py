#!/usr/bin/env python3
"""Example for aiohttp.web class based views
"""


import asyncio
import functools
import json
from aiohttp.web import json_response, Application, Response, View


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
    app.router.add_route('GET', '/', index)
    app.router.add_route('GET', '/get', MyView)
    app.router.add_route('POST', '/post', MyView)

    handler = app.make_handler()
    srv = await loop.create_server(handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return srv, handler


loop = asyncio.get_event_loop()
srv, handler = loop.run_until_complete(init(loop))
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(handler.finish_connections())
