#!/usr/bin/env python3
"""Example for aiohttp.web class based views
"""


import asyncio
from aiohttp import hdrs
from aiohttp.web import (json_response, Application, Response,
                         HTTPMethodNotAllowed)


ALL_METHODS = {hdrs.METH_CONNECT, hdrs.METH_HEAD, hdrs.METH_GET,
               hdrs.METH_DELETE, hdrs.METH_OPTIONS, hdrs.METH_PATCH,
               hdrs.METH_POST, hdrs.METH_PUT, hdrs.METH_TRACE}


class BaseView:
    def __init__(self, request):
        self.request = request

    def __await__(self):
        method = getattr(self, self.request.method, None)
        if method is None:
            allowed_methods = {m for m in ALL_METHODS if hasattr(self, m)}
            return HTTPMethodNotAllowed(self.request.method, allowed_methods)
        resp = method().__await__()
        return resp


class View(BaseView):

    async def GET(self):
        return Response(text='OK')


async def index(request):
    txt  = """
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
            <li><a href="/put">/put</a> Returns PUT data.
            <li><a href="/delete">/delete</a> Returns DELETE data.
          </ul>
        </body>
      </html>
    """
    return Response(text=txt, content_type='text/html')


async def init(loop):
    app = Application(loop=loop)
    app.router.add_route('GET', '/', index)
    app.router.add_route('GET', '/get', View)
    app.router.add_route('POST', '/post', View)
    app.router.add_route('PUT', '/put', View)
    app.router.add_route('DELETE', '/delete', View)

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
