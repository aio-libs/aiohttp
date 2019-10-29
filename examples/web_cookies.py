#!/usr/bin/env python3
"""Example for aiohttp.web basic server with cookies.
"""

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

class RedirectionResponse(web.Response):
    def __init__(self, location: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers['Location'] = location
        self.set_status(302)


async def root(request):
    resp = web.Response(content_type='text/html')
    resp.text = tmpl.format(pformat(request.cookies))
    return resp


async def login(request):
    resp = RedirectionResponse(location='/')
    resp.set_cookie('AUTH', 'secret')
    return resp


async def logout(request):
    resp = RedirectionResponse(location='/')
    resp.del_cookie('AUTH')
    return resp


def init():
    app = web.Application()
    app.router.add_get('/', root)
    app.router.add_get('/login', login)
    app.router.add_get('/logout', logout)
    return app


web.run_app(init())
