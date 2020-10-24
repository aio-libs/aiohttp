#!/usr/bin/env python3
"""Example for aiohttp.web basic server with cookies.
"""

from pprint import pformat

from aiohttp import web

tmpl = """\
<html>
    <body>
        <a href="/login">Login</a><br/>
        <a href="/logout">Logout</a><br/>
        <pre>{}</pre>
    </body>
</html>"""


async def root(request):
    resp = web.Response(content_type="text/html")
    resp.text = tmpl.format(pformat(request.cookies))
    return resp


async def login(request):
    resp = web.HTTPFound(location="/")
    resp.set_cookie("AUTH", "secret")
    return resp


async def logout(request):
    resp = web.HTTPFound(location="/")
    resp.del_cookie("AUTH")
    return resp


def init(loop):
    app = web.Application(loop=loop)
    app.router.add_get("/", root)
    app.router.add_get("/login", login)
    app.router.add_get("/logout", logout)
    return app


web.run_app(init())
