#!/usr/bin/env python3
"""Example for aiohttp.web basic server with decorator definition for routes."""

import textwrap

from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/")
async def intro(request):
    txt = textwrap.dedent(
        """\
        Type {url}/hello/John  {url}/simple or {url}/change_body
        in browser url bar
    """
    ).format(url="127.0.0.1:8080")
    binary = txt.encode("utf8")
    resp = web.StreamResponse()
    resp.content_length = len(binary)
    resp.content_type = "text/plain"
    await resp.prepare(request)
    await resp.write(binary)
    return resp


@routes.get("/simple")
async def simple(request):
    return web.Response(text="Simple answer")


@routes.get("/change_body")
async def change_body(request):
    resp = web.Response()
    resp.body = b"Body changed"
    resp.content_type = "text/plain"
    return resp


@routes.get("/hello")
async def hello(request):
    resp = web.StreamResponse()
    name = request.match_info.get("name", "Anonymous")
    answer = ("Hello, " + name).encode("utf8")
    resp.content_length = len(answer)
    resp.content_type = "text/plain"
    await resp.prepare(request)
    await resp.write(answer)
    await resp.write_eof()
    return resp


def init():
    app = web.Application()
    app.router.add_routes(routes)
    return app


web.run_app(init())
