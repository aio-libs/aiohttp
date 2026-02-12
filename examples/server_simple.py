# server_simple.py
import asyncio

from aiohttp import ClientSession, web


async def handle(request: web.Request) -> web.StreamResponse:
    name = request.match_info.get("name", "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)


async def wshandle(request: web.Request) -> web.StreamResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type is web.WSMsgType.TEXT:
            await ws.send_str(f"Hello, {msg.data}")
        elif msg.type is web.WSMsgType.BINARY:
            await ws.send_bytes(msg.data)
        elif msg.type is web.WSMsgType.CLOSE:
            break

    return ws


def init() -> web.Application:
    app = web.Application()
    app.add_routes(
        [web.get("/", handle), web.get("/echo", wshandle), web.get("/{name}", handle)]
    )
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
            assert await resp.text() == "Hello, Anonymous"
            print("OK: GET / -> Hello, Anonymous")

        async with session.get(f"{base_url}/John") as resp:
            assert resp.status == 200
            assert await resp.text() == "Hello, John"
            print("OK: GET /John -> Hello, John")

    async with ClientSession() as session:
        async with session.ws_connect(f"ws://localhost:{port}/echo") as ws:
            await ws.send_str("Hello")
            msg = await ws.receive_str()
            assert msg == "Hello, Hello"
            print("OK: WS /echo -> Hello, Hello")

    print("\nAll tests passed!")


async def main() -> None:
    runner, port = await run_test_server()
    try:
        await run_tests(port)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
