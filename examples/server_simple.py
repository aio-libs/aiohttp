# server_simple.py
from typing import TYPE_CHECKING

from aiohttp import web


async def handle(request: web.Request) -> web.StreamResponse:
    name = request.match_info.get("name", "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)


async def wshandle(request: web.Request) -> web.StreamResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type is web.WSMsgType.TEXT:
            data = msg.data
            if TYPE_CHECKING:
                assert isinstance(data, str)
            await ws.send_str(f"Hello, {data}")
        elif msg.type is web.WSMsgType.BINARY:
            await ws.send_bytes(msg.data)
        elif msg.type is web.WSMsgType.CLOSE:
            break

    return ws


app = web.Application()
app.add_routes(
    [web.get("/", handle), web.get("/echo", wshandle), web.get("/{name}", handle)]
)

web.run_app(app)
