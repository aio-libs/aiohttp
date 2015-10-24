import pytest

import asyncio

from aiohttp import web, websocket
from aiohttp.websocket_client import MsgType, ws_connect


async def create_server(loop, port, method, path, route_handler):
    app = web.Application(loop=loop)
    app.router.add_route(method, path, route_handler)
    handler = app.make_handler(keep_alive_on=False)
    return await loop.create_server(handler, '127.0.0.1', port)


@pytest.mark.run_loop
async def test_await(loop, create_server):
    closed = asyncio.Future(loop=loop)

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            assert msg.tp == MsgType.text
            s = msg.data
            ws.send_str(s + '/answer')
        await ws.close()
        closed.set_result(1)
        return ws

    app, url = await create_server(proto='ws')
    app.router.add_route('GET', '/', handler)  # returns server
    resp = await ws_connect(url, loop=loop)

    items = ['q1', 'q2', 'q3']
    for item in items:
        resp.send_str(item)
        msg = await resp.receive()
        assert msg.tp == websocket.MSG_TEXT
        assert item + '/answer' == msg.data

    await resp.close()
    await closed
