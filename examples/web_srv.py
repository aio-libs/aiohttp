#!/usr/bin/env python3
"""Example for aiohttp.web basic server
"""

import asyncio
import textwrap

from aiohttp.web import Application, Response, StreamResponse, run_app


async def intro(request):
    txt = textwrap.dedent("""\
        Type {url}/hello/John  {url}/simple or {url}/change_body
        in browser url bar
    """).format(url='127.0.0.1:8080')
    binary = txt.encode('utf8')
    resp = StreamResponse()
    resp.content_length = len(binary)
    resp.content_type = 'text/plain'
    await resp.prepare(request)
    resp.write(binary)
    return resp


async def simple(request):
    return Response(text="Simple answer")


async def change_body(request):
    resp = Response()
    resp.body = b"Body changed"
    resp.content_type = 'text/plain'
    return resp


async def hello(request):
    resp = StreamResponse()
    name = request.match_info.get('name', 'Anonymous')
    answer = ('Hello, ' + name).encode('utf8')
    resp.content_length = len(answer)
    resp.content_type = 'text/plain'
    await resp.prepare(request)
    resp.write(answer)
    await resp.write_eof()
    return resp


async def init(loop):
    app = Application()
    app.router.add_get('/', intro)
    app.router.add_get('/simple', simple)
    app.router.add_get('/change_body', change_body)
    app.router.add_get('/hello/{name}', hello)
    app.router.add_get('/hello', hello)
    return app

loop = asyncio.get_event_loop()
app = loop.run_until_complete(init(loop))
run_app(app)
