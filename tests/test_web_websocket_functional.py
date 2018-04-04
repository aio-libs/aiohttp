"""HTTP websocket server functional tests"""

import asyncio

import pytest

import aiohttp
from aiohttp import web
from aiohttp.http import WSMsgType


@pytest.fixture
def ceil(mocker):
    def ceil(val):
        return val

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil


async def test_websocket_can_prepare(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            raise web.HTTPUpgradeRequired()

        return web.Response()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    assert resp.status == 426


async def test_websocket_json(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.HTTPUpgradeRequired()

        await ws.prepare(request)
        msg = await ws.receive()

        msg_json = msg.json()
        answer = msg_json['test']
        await ws.send_str(answer)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    await ws.send_str(payload)

    resp = await ws.receive()
    assert resp.data == expected_value


async def test_websocket_json_invalid_message(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            await ws.receive_json()
        except ValueError:
            await ws.send_str('ValueError was raised')
        else:
            raise Exception('No Exception')
        finally:
            await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    payload = 'NOT A VALID JSON STRING'
    await ws.send_str(payload)

    data = await ws.receive_str()
    assert 'ValueError was raised' in data


async def test_websocket_send_json(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        data = await ws.receive_json()
        await ws.send_json(data)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    expected_value = 'value'
    await ws.send_json({'test': expected_value})

    data = await ws.receive_json()
    assert data['test'] == expected_value


async def test_websocket_receive_json(loop, aiohttp_client):

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        data = await ws.receive_json()
        answer = data['test']
        await ws.send_str(answer)

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    await ws.send_str(payload)

    resp = await ws.receive()
    assert resp.data == expected_value


async def test_send_recv_text(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        msg = await ws.receive_str()
        await ws.send_str(msg+'/answer')
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    await ws.send_str('ask')
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert 'ask/answer' == msg.data

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    assert ws.closed
    assert ws.close_code == 1000

    await closed


async def test_send_recv_bytes(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        msg = await ws.receive_bytes()
        await ws.send_bytes(msg+b'/answer')
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    await ws.send_bytes(b'ask')
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert b'ask/answer' == msg.data

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    assert ws.closed
    assert ws.close_code == 1000

    await closed


async def test_send_recv_json(loop, aiohttp_client):
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        data = await ws.receive_json()
        await ws.send_json({'response': data['request']})
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')

    await ws.send_str('{"request": "test"}')
    msg = await ws.receive()
    data = msg.json()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert data['response'] == 'test'

    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    await ws.close()

    await closed


async def test_close_timeout(loop, aiohttp_client):
    aborted = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(timeout=0.1)
        await ws.prepare(request)
        assert 'request' == (await ws.receive_str())
        await ws.send_str('reply')
        begin = ws._loop.time()
        assert (await ws.close())
        elapsed = ws._loop.time() - begin
        assert elapsed < 0.201, \
            'close() should have returned before ' \
            'at most 2x timeout.'
        assert ws.close_code == 1006
        assert isinstance(ws.exception(), asyncio.TimeoutError)
        aborted.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    await ws.send_str('request')
    assert 'reply' == (await ws.receive_str())

    # The server closes here.  Then the client sends bogus messages with an
    # internval shorter than server-side close timeout, to make the server
    # hanging indefinitely.
    await asyncio.sleep(0.08, loop=loop)
    msg = await ws._reader.read()
    assert msg.type == WSMsgType.CLOSE
    await ws.send_str('hang')

    # i am not sure what do we test here
    # under uvloop this code raises RuntimeError
    try:
        await asyncio.sleep(0.08, loop=loop)
        await ws.send_str('hang')
        await asyncio.sleep(0.08, loop=loop)
        await ws.send_str('hang')
        await asyncio.sleep(0.08, loop=loop)
        await ws.send_str('hang')
    except RuntimeError:
        pass

    await asyncio.sleep(0.08, loop=loop)
    assert (await aborted)

    await ws.close()


async def test_concurrent_close(loop, aiohttp_client):

    srv_ws = None

    async def handler(request):
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(
            autoclose=False, protocols=('foo', 'bar'))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSING

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSING

        await asyncio.sleep(0, loop=loop)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSED

        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoclose=False,
                                 protocols=('eggs', 'bar'))

    await srv_ws.close(code=1007)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await asyncio.sleep(0, loop=loop)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED


async def test_auto_pong_with_closing_by_peer(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.receive()

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == 1000
        assert msg.extra == 'exit message'
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoclose=False, autoping=False)
    await ws.ping()
    await ws.send_str('ask')

    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    await ws.close(code=1000, message='exit message')
    await closed


async def test_ping(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.ping('data')
        await ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoping=False)

    msg = await ws.receive()
    assert msg.type == WSMsgType.PING
    assert msg.data == b'data'
    await ws.pong()
    await ws.close()
    await closed


async def aiohttp_client_ping(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        await ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoping=False)

    await ws.ping('data')
    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b'data'
    await ws.pong()
    await ws.close()


async def test_pong(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(autoping=False)
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.PING
        await ws.pong('data')

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == 1000
        assert msg.extra == 'exit message'
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoping=False)

    await ws.ping('data')
    msg = await ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b'data'

    await ws.close(code=1000, message='exit message')

    await closed


async def test_change_status(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        ws.set_status(200)
        assert 200 == ws.status
        await ws.prepare(request)
        assert 101 == ws.status
        await ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoping=False)

    await ws.close()
    await closed
    await ws.close()


async def test_handle_protocol(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(protocols=('foo', 'bar'))
        await ws.prepare(request)
        await ws.close()
        assert 'bar' == ws.ws_protocol
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', protocols=('eggs', 'bar'))

    await ws.close()
    await closed


async def test_server_close_handshake(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(protocols=('foo', 'bar'))
        await ws.prepare(request)
        await ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoclose=False,
                                 protocols=('eggs', 'bar'))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE
    await ws.close()
    await closed


async def aiohttp_client_close_handshake(loop, aiohttp_client, ceil):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(
            autoclose=False, protocols=('foo', 'bar'))
        await ws.prepare(request)

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert not ws.closed
        await ws.close()
        assert ws.closed
        assert ws.close_code == 1007

        msg = await ws.receive()
        assert msg.type == WSMsgType.CLOSED

        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoclose=False,
                                 protocols=('eggs', 'bar'))

    await ws.close(code=1007)
    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED
    await closed


async def test_server_close_handshake_server_eats_client_messages(
    loop, aiohttp_client
):
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse(protocols=('foo', 'bar'))
        await ws.prepare(request)
        await ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/', autoclose=False, autoping=False,
                                 protocols=('eggs', 'bar'))

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSE

    await ws.send_str('text')
    await ws.send_bytes(b'bytes')
    await ws.ping()

    await ws.close()
    await closed


async def test_receive_timeout(loop, aiohttp_client):
    raised = False

    async def handler(request):
        ws = web.WebSocketResponse(receive_timeout=0.1)
        await ws.prepare(request)

        try:
            await ws.receive()
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    await ws.receive()
    await ws.close()
    assert raised


async def test_custom_receive_timeout(loop, aiohttp_client):
    raised = False

    async def handler(request):
        ws = web.WebSocketResponse(receive_timeout=None)
        await ws.prepare(request)

        try:
            await ws.receive(0.1)
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    await ws.receive()
    await ws.close()
    assert raised


async def test_heartbeat(loop, aiohttp_client, ceil):

    async def handler(request):
        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)
        await ws.receive()
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_get('/', handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect('/', autoping=False)
    msg = await ws.receive()

    assert msg.type == aiohttp.WSMsgType.ping

    await ws.close()


async def test_heartbeat_no_pong(loop, aiohttp_client, ceil):
    cancelled = False

    async def handler(request):
        nonlocal cancelled

        ws = web.WebSocketResponse(heartbeat=0.05)
        await ws.prepare(request)

        try:
            await ws.receive()
        except asyncio.CancelledError:
            cancelled = True

        return ws

    app = web.Application()
    app.router.add_get('/', handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect('/', autoping=False)
    msg = await ws.receive()
    assert msg.type == aiohttp.WSMsgType.ping
    await ws.receive()

    assert cancelled


async def test_server_ws_async_for(loop, aiohttp_server):
    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            assert msg.type == aiohttp.WSMsgType.TEXT
            s = msg.data
            await ws.send_str(s + '/answer')
        await ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    server = await aiohttp_server(app)

    async with aiohttp.ClientSession(loop=loop) as sm:
        async with sm.ws_connect(server.make_url('/')) as resp:

            items = ['q1', 'q2', 'q3']
            for item in items:
                await resp.send_str(item)
                msg = await resp.receive()
                assert msg.type == aiohttp.WSMsgType.TEXT
                assert item + '/answer' == msg.data

            await resp.close()
            await closed


async def test_closed_async_for(loop, aiohttp_client):

    closed = loop.create_future()

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        messages = []
        async for msg in ws:
            messages.append(msg)
            if 'stop' == msg.data:
                await ws.send_str('stopping')
                await ws.close()

        assert 1 == len(messages)
        assert messages[0].type == WSMsgType.TEXT
        assert messages[0].data == 'stop'

        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = await aiohttp_client(app)

    ws = await client.ws_connect('/')
    await ws.send_str('stop')
    msg = await ws.receive()
    assert msg.type == WSMsgType.TEXT
    assert msg.data == 'stopping'

    await ws.close()
    await closed


async def test_websocket_disable_keepalive(loop, aiohttp_client):
    async def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.Response(text='OK')
        assert request.protocol._keepalive
        await ws.prepare(request)
        assert not request.protocol._keepalive
        assert not request.protocol._keepalive_handle

        await ws.send_str('OK')
        await ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = await aiohttp_client(app)

    resp = await client.get('/')
    txt = await resp.text()
    assert txt == 'OK'

    ws = await client.ws_connect('/')
    data = await ws.receive_str()
    assert data == 'OK'
