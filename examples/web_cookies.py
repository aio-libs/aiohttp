#!/usr/bin/env python3
"""Example for aiohttp.web basic server with cookies.
"""

import asyncio
from aiohttp import web


tmpl = '''\
<html>
    <body>
        <a href="/login">Login</a><br/>
        <a href="/logout">Logout</a><br/>
        {}
    </body>
</html>'''


@asyncio.coroutine
def root(request):
    resp = web.Response(content_type='text/html')
    resp.text = tmpl.format(request.cookies)
    return resp


@asyncio.coroutine
def login(request):
    resp = web.HTTPFound(location='/')
    resp.set_cookie('AUTH', 'secret')
    return resp


@asyncio.coroutine
def logout(request):
    resp = web.HTTPFound(location='/')
    resp.del_cookie('AUTH')
    return resp


@asyncio.coroutine
def init(loop):
    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', root)
    app.router.add_route('GET', '/login', login)
    app.router.add_route('GET', '/logout', logout)

    handler = app.make_handler()
    srv = yield from loop.create_server(handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return srv, handler

loop = asyncio.get_event_loop()
srv, handler = loop.run_until_complete(init(loop))
try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(handler.finish_connections())
