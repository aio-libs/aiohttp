#!/usr/bin/env python3
"""Example for aiohttp.web basic server."""

import asyncio
import textwrap

import aiohttp
from aiohttp import web


async def intro(request: web.Request) -> web.StreamResponse:
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


async def simple(request: web.Request) -> web.StreamResponse:
    return web.Response(text="Simple answer")


async def change_body(request: web.Request) -> web.StreamResponse:
    resp = web.Response()
    resp.body = b"Body changed"
    resp.content_type = "text/plain"
    return resp


async def hello(request: web.Request) -> web.StreamResponse:
    resp = web.StreamResponse()
    name = request.match_info.get("name", "Anonymous")
    answer = ("Hello, " + name).encode("utf8")
    resp.content_length = len(answer)
    resp.content_type = "text/plain"
    await resp.prepare(request)
    await resp.write(answer)
    await resp.write_eof()
    return resp


def init() -> web.Application:
    app = web.Application()
    app.router.add_get("/", intro)
    app.router.add_get("/simple", simple)
    app.router.add_get("/change_body", change_body)
    app.router.add_get("/hello/{name}", hello)
    app.router.add_get("/hello", hello)
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

    async with aiohttp.ClientSession() as session:
        print("=== Test 1: Intro page ===")
        async with session.get(f"{base_url}/") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert "hello" in text.lower()
            print(f"OK: Got intro page ({len(text)} bytes)")

        print("=== Test 2: Simple response ===")
        async with session.get(f"{base_url}/simple") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Simple answer"
            print(f"OK: Got '{text}'")

        print("=== Test 3: Change body ===")
        async with session.get(f"{base_url}/change_body") as resp:
            assert resp.status == 200
            body = await resp.read()
            assert body == b"Body changed"
            print(f"OK: Got '{body.decode()}'")

        print("=== Test 4: Hello with name ===")
        async with session.get(f"{base_url}/hello/World") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Hello, World"
            print(f"OK: Got '{text}'")

        print("=== Test 5: Hello anonymous ===")
        async with session.get(f"{base_url}/hello") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Hello, Anonymous"
            print(f"OK: Got '{text}'")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
