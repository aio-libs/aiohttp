#!/usr/bin/env python3
"""Example for aiohttp.web class based views."""

import asyncio
import functools
import json

from aiohttp import ClientSession, web


class MyView(web.View):
    async def get(self) -> web.StreamResponse:
        return web.json_response(
            {
                "method": self.request.method,
                "args": dict(self.request.rel_url.query),
                "headers": dict(self.request.headers),
            },
            dumps=functools.partial(json.dumps, indent=4),
        )

    async def post(self) -> web.StreamResponse:
        data = await self.request.post()
        return web.json_response(
            {
                "method": self.request.method,
                "data": dict(data),
                "headers": dict(self.request.headers),
            },
            dumps=functools.partial(json.dumps, indent=4),
        )


async def index(request: web.Request) -> web.StreamResponse:
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
    return web.Response(text=txt, content_type="text/html")


def init() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/get", MyView)
    app.router.add_post("/post", MyView)
    return app


async def run_test_server() -> tuple[web.AppRunner, int]:
    """Start the server on a dynamic port for testing."""
    runner = web.AppRunner(init())
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 0)
    await site.start()
    assert site._server is not None
    port: int = site._server.sockets[0].getsockname()[1]
    return runner, port


async def run_tests(port: int) -> None:
    """Run all tests against the server."""
    base_url = f"http://localhost:{port}"
    async with ClientSession() as session:
        async with session.get(f"{base_url}/") as resp:
            assert resp.status == 200
            assert "text/html" in (resp.content_type or "")
            print("OK: GET / -> HTML index page")

        async with session.get(f"{base_url}/get") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["method"] == "GET"
            print("OK: GET /get -> JSON with method=GET")

        async with session.post(f"{base_url}/post", data={"key": "value"}) as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["method"] == "POST"
            print("OK: POST /post -> JSON with method=POST")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
