import pytest

import aiohttp
from aiohttp import helpers, web


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


async def test_client_ws_async_with(loop, test_server):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)

    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as client:
        async with client.ws_connect(server.make_url('/')) as ws:
            ws.send_str('request')
            msg = await ws.receive()
            assert msg.data == 'request/answer'

        assert ws.closed


async def test_client_ws_async_with_send(loop, test_server):
    # send_xxx methods have to return awaitable objects

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)

    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as client:
        async with client.ws_connect(server.make_url('/')) as ws:
            await ws.send_str('request')
            msg = await ws.receive()
            assert msg.data == 'request/answer'

        assert ws.closed


async def test_client_ws_async_with_shortcut(loop, test_server):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    server = await test_server(app)

    async with aiohttp.ClientSession(loop=loop) as client:
        async with client.ws_connect(server.make_url('/')) as ws:
            ws.send_str('request')
            msg = await ws.receive()
            assert msg.data == 'request/answer'

        assert ws.closed


async def test_closed_async_for(loop, test_client):

    closed = helpers.create_future(loop)

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            ws.send_bytes(b'started')
            await ws.receive_bytes()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = await test_client(app)
    resp = await client.ws_connect('/')

    messages = []
    async for msg in resp:
        messages.append(msg)
        if b'started' == msg.data:
            resp.send_bytes(b'ask')
            await resp.close()

    assert 1 == len(messages)
    assert messages[0].type == aiohttp.WSMsgType.BINARY
    assert messages[0].data == b'started'
    assert resp.closed

    await closed
