#!/usr/bin/env python3
"""Example for aiohttp.web basic server with cookies.
"""

from pprint import pformat

from aiohttp import web
from aiohttp.web_request import Request

tmpl = """\
<html>
    <body>
        <a href="/login">Login</a><br/>
        <a href="/logout">Logout</a><br/>
        <pre>{}</pre>
    </body>
</html>"""


async def root(request: Request) -> web.StreamResponse:
    resp = web.Response(content_type="text/html")
    resp.text = tmpl.format(pformat(request.cookies))
    return resp


async def login(request: Request) -> None:
    exc = web.HTTPFound(location="/")
    exc.set_cookie("AUTH", "secret")
    raise exc


async def logout(request: Request) -> None:
    exc = web.HTTPFound(location="/")
    exc.del_cookie("AUTH")
    raise exc


def init() -> web.Application:
    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/login", login)
    app.router.add_get("/logout", logout)
    return app


web.run_app(init())
