import pytest

import aiohttp
from aiohttp import web

async def test_client_ws_async_for(loop, create_server):
    items = ['q1', 'q2', 'q3']

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for i in items:
            ws.send_str(i)
        await ws.close()
        return ws

    app, url = await create_server(proto='ws')
    app.router.add_route('GET', '/', handler)
    resp = await aiohttp.ws_connect(url, loop=loop)
    it = iter(items)
    async for msg in resp:
        assert msg.data == next(it)

    with pytest.raises(StopIteration):
        next(it)

    assert resp.closed


async def test_client_ws_async_with(loop, create_app_and_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app, client = await create_app_and_client(
        server_params=dict(proto='ws'))
    app.router.add_route('GET', '/', handler)

    async with client.ws_connect('/') as ws:
        ws.send_str('request')
        msg = await ws.receive()
        assert msg.data == 'request/answer'

    assert ws.closed


async def test_client_ws_async_with_shortcut(loop, create_server):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app, url = await create_server(proto='ws')
    app.router.add_route('GET', '/', handler)

    async with aiohttp.ws_connect(url, loop=loop) as ws:
        ws.send_str('request')
        msg = await ws.receive()
        assert msg.data == 'request/answer'

    assert ws.closed
