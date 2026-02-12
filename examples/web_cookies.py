#!/usr/bin/env python3
"""Example for aiohttp.web basic server with cookies."""

import asyncio
from pprint import pformat
from typing import NoReturn

from aiohttp import ClientSession, web

tmpl = """\
<html>
    <body>
        <a href="/login">Login</a><br/>
        <a href="/logout">Logout</a><br/>
        <pre>{}</pre>
    </body>
</html>"""


async def root(request: web.Request) -> web.StreamResponse:
    resp = web.Response(content_type="text/html")
    resp.text = tmpl.format(pformat(request.cookies))
    return resp


async def login(request: web.Request) -> NoReturn:
    exc = web.HTTPFound(location="/")
    exc.set_cookie("AUTH", "secret")
    raise exc


async def logout(request: web.Request) -> NoReturn:
    exc = web.HTTPFound(location="/")
    exc.del_cookie("AUTH")
    raise exc


def init() -> web.Application:
    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/login", login)
    app.router.add_get("/logout", logout)
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
            print("OK: GET / -> HTML page")

        async with session.get(f"{base_url}/login", allow_redirects=False) as resp:
            assert resp.status == 302
            assert "AUTH" in {c.key for c in resp.cookies.values()}
            print("OK: GET /login -> 302 with AUTH cookie")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
