import asyncio

import async_timeout
import pytest

import aiohttp
from aiohttp import hdrs, web


@pytest.fixture
def ceil(mocker):
    def ceil(val):
        return val

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil


async def test_send_recv_text(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg+'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')
    await resp.send_str('ask')

    assert resp.get_extra_info('socket') is not None

    data = await resp.receive_str()
    assert data == 'ask/answer'
    await resp.close()

    assert resp.get_extra_info('socket') is None


async def test_send_recv_bytes_bad_type(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg+'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')
    await resp.send_str('ask')

    with pytest.raises(TypeError):
        await resp.receive_bytes()
        await resp.close()


async def test_send_recv_bytes(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg+b'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    await resp.send_bytes(b'ask')

    data = await resp.receive_bytes()
    assert data == b'ask/answer'

    await resp.close()


async def test_send_recv_text_bad_type(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg+b'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    await resp.send_bytes(b'ask')

    with pytest.raises(TypeError):
        await resp.receive_str()

        await resp.close()


async def test_send_recv_json(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        data = await ws.receive_json()
        await ws.send_json({'response': data['request']})
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')
    payload = {'request': 'test'}
    await resp.send_json(payload)

    data = await resp.receive_json()
    assert data['response'] == payload['request']
    await resp.close()


async def test_ping_pong(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.ping()
        await ws.send_bytes(msg+b'/answer')
        try:
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    await resp.ping()
    await resp.send_bytes(b'ask')

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert msg.data == b'ask/answer'

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    await resp.close()
    await closed


async def test_ping_pong_manual(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.ping()
        await ws.send_bytes(msg+b'/answer')
        try:
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', autoping=False)

    await resp.ping()
    await resp.send_bytes(b'ask')

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.PONG

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.PING
    await resp.pong()

    msg = await resp.receive()
    assert msg.data == b'ask/answer'

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    await closed


async def test_close(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str('test')

        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    await resp.send_bytes(b'ask')

    closed = await resp.close()
    assert closed
    assert resp.closed
    assert resp.close_code == 1000

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED


async def test_concurrent_close(loop, aiohttp_client):
    client_ws = None

    async def handler(request):
        nonlocal client_ws
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str('test')

        await client_ws.close()

        msg = await ws.receive()
        assert msg.type == aiohttp.WSMsgType.CLOSE
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    ws = client_ws = await client.ws_connect('/')

    await ws.send_bytes(b'ask')

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSING

    await asyncio.sleep(0.01, loop=loop)
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED


async def test_close_from_server(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            await ws.receive_bytes()
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    await resp.send_bytes(b'ask')

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert resp.closed

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED

    await closed


async def test_close_manual(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_bytes()
        await ws.send_str('test')

        try:
            await ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', autoclose=False)
    await resp.send_bytes(b'ask')

    msg = await resp.receive()
    assert msg.data == 'test'

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''
    assert not resp.closed

    await resp.close()
    await closed
    assert resp.closed


async def test_close_timeout(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str('test')
        await asyncio.sleep(1, loop=loop)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', timeout=0.2, autoclose=False)

    await resp.send_bytes(b'ask')

    msg = await resp.receive()
    assert msg.data == 'test'
    assert msg.type == aiohttp.WSMsgType.TEXT

    msg = await resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


async def test_close_cancel(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive_bytes()
        await ws.send_str('test')
        await asyncio.sleep(10, loop=loop)

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', autoclose=False)

    await resp.send_bytes(b'ask')

    text = await resp.receive()
    assert text.data == 'test'

    t = loop.create_task(resp.close())
    await asyncio.sleep(0.1, loop=loop)
    t.cancel()
    await asyncio.sleep(0.1, loop=loop)
    assert resp.closed
    assert resp.exception() is None


async def test_override_default_headers(loop, aiohttp_client):

    async def handler(request):
        assert request.headers[hdrs.SEC_WEBSOCKET_VERSION] == '8'
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_str('answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    headers = {hdrs.SEC_WEBSOCKET_VERSION: '8'}
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', headers=headers)
    msg = await resp.receive()
    assert msg.data == 'answer'
    await resp.close()


async def test_additional_headers(loop, aiohttp_client):

    async def handler(request):
        assert request.headers['x-hdr'] == 'xtra'
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.send_str('answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', headers={'x-hdr': 'xtra'})
    msg = await resp.receive()
    assert msg.data == 'answer'
    await resp.close()


async def test_recv_protocol_error(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_str()
        ws._writer.transport.write(b'01234' * 100)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')
    await resp.send_str('ask')

    msg = await resp.receive()
    assert msg.type == aiohttp.WSMsgType.ERROR
    assert type(msg.data) is aiohttp.WebSocketError
    assert msg.data.args[0] == 'Received frame with non-zero reserved bits'
    assert msg.extra is None
    await resp.close()


async def test_recv_timeout(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive_str()

        await asyncio.sleep(0.1, loop=request.app.loop)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')
    await resp.send_str('ask')

    with pytest.raises(asyncio.TimeoutError):
        with async_timeout.timeout(0.01, loop=app.loop):
            await resp.receive()

    await resp.close()


async def test_receive_timeout(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', receive_timeout=0.1)

    with pytest.raises(asyncio.TimeoutError):
        await resp.receive(0.05)

    await resp.close()


async def test_custom_receive_timeout(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    with pytest.raises(asyncio.TimeoutError):
        await resp.receive(0.05)

    await resp.close()


async def test_heartbeat(loop, aiohttp_client, ceil):
    ping_received = False

    async def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        if msg.type == aiohttp.WSMsgType.ping:
            ping_received = True
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', heartbeat=0.01)
    await asyncio.sleep(0.1)
    await resp.receive()
    await resp.close()

    assert ping_received


async def test_heartbeat_no_pong(loop, aiohttp_client, ceil):
    ping_received = False

    async def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)
        msg = await ws.receive()
        if msg.type == aiohttp.WSMsgType.ping:
            ping_received = True
        await ws.receive()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', heartbeat=0.05)

    await resp.receive()
    await resp.receive()

    assert ping_received


async def test_send_recv_compress(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg+'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', compress=15)
    await resp.send_str('ask')

    assert resp.compress == 15

    data = await resp.receive_str()
    assert data == 'ask/answer'

    await resp.close()
    assert resp.get_extra_info('socket') is None


async def test_send_recv_compress_wbits(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_str()
        await ws.send_str(msg+'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/', compress=9)
    await resp.send_str('ask')

    # Client indicates supports wbits 15
    # Server supports wbit 15 for decode
    assert resp.compress == 15

    data = await resp.receive_str()
    assert data == 'ask/answer'

    await resp.close()
    assert resp.get_extra_info('socket') is None


async def test_send_recv_compress_wbit_error(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg+b'/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    with pytest.raises(ValueError):
        await client.ws_connect('/', compress=1)


async def test_ws_client_async_for(loop, aiohttp_client):
    items = ['q1', 'q2', 'q3']

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        for i in items:
            await ws.send_str(i)
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')
    it = iter(items)
    async for msg in resp:
        assert msg.data == next(it)

    with pytest.raises(StopIteration):
        next(it)

    assert resp.closed


async def test_ws_async_with(loop, aiohttp_server):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        await ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    server = await aiohttp_server(app)

    async with aiohttp.ClientSession(loop=loop) as client:
        async with client.ws_connect(server.make_url('/')) as ws:
            await ws.send_str('request')
            msg = await ws.receive()
            assert msg.data == 'request/answer'

        assert ws.closed


async def test_ws_async_with_send(loop, aiohttp_server):
    # send_xxx methods have to return awaitable objects

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        await ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    server = await aiohttp_server(app)

    async with aiohttp.ClientSession(loop=loop) as client:
        async with client.ws_connect(server.make_url('/')) as ws:
            await ws.send_str('request')
            msg = await ws.receive()
            assert msg.data == 'request/answer'

        assert ws.closed


async def test_ws_async_with_shortcut(loop, aiohttp_server):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive()
        await ws.send_str(msg.data + '/answer')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession(loop=loop) as client:
        async with client.ws_connect(server.make_url('/')) as ws:
            await ws.send_str('request')
            msg = await ws.receive()
            assert msg.data == 'request/answer'

        assert ws.closed


async def test_closed_async_for(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            await ws.send_bytes(b'started')
            await ws.receive_bytes()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)
    resp = await client.ws_connect('/')

    messages = []
    async for msg in resp:
        messages.append(msg)
        if b'started' == msg.data:
            await resp.send_bytes(b'ask')
            await resp.close()

    assert 1 == len(messages)
    assert messages[0].type == aiohttp.WSMsgType.BINARY
    assert messages[0].data == b'started'
    assert resp.closed

    await closed
