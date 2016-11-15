#!/usr/bin/env python3
"""Example for aiohttp.web basic server with cookies.
"""

import asyncio
from pprint import pformat

from aiohttp import web


tmpl = '''\
<html>
    <body>
        <a href="/login">Login</a><br/>
        <a href="/logout">Logout</a><br/>
        <pre>{}</pre>
    </body>
</html>'''


@asyncio.coroutine
def root(request):
    resp = web.Response(content_type='text/html')
    resp.text = tmpl.format(pformat(request.cookies))
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
    app.router.add_get('/', root)
    app.router.add_get('/login', login)
    app.router.add_get('/logout', logout)
    return app


loop = asyncio.get_event_loop()
app = loop.run_until_complete(init(loop))
web.run_app(app)
