import pytest

from aiohttp import web

async def test_client_ws_async_for(loop, test_client):
    items = ['q1', 'q2', 'q3']

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for i in items:
            ws.send_str(i)
        await ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)

    client = await test_client(app)
    resp = await client.ws_connect('/')
    it = iter(items)
    async for msg in resp:
        assert msg.data == next(it)

    with pytest.raises(StopIteration):
        next(it)

    assert resp.closed


async def test_client_ws_async_with(loop, test_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)

    client = await test_client(app)

    async with client.ws_connect('/') as ws:
        ws.send_str('request')
        msg = await ws.receive()
        assert msg.data == 'request/answer'

    assert ws.closed


async def test_client_ws_async_with_shortcut(loop, test_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)

    async with client.ws_connect('/') as ws:
        ws.send_str('request')
        msg = await ws.receive()
        assert msg.data == 'request/answer'

    assert ws.closed
