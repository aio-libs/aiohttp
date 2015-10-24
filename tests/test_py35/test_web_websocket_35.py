import pytest

import asyncio

from aiohttp import web, websocket
from aiohttp.websocket_client import MsgType, ws_connect


@pytest.mark.run_loop
async def test_server_ws_async_for(loop, create_server):
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
    app.router.add_route('GET', '/', handler)
    resp = await ws_connect(url, loop=loop)

    items = ['q1', 'q2', 'q3']
    for item in items:
        resp.send_str(item)
        msg = await resp.receive()
        assert msg.tp == websocket.MSG_TEXT
        assert item + '/answer' == msg.data

    await resp.close()
    await closed
