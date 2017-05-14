import asyncio

import pytest

import aiohttp
from aiohttp import hdrs, helpers, web


@pytest.fixture
def ceil(mocker):
    def ceil(val):
        return val

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil


@asyncio.coroutine
def test_send_recv_text(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_str()
        yield from ws.send_str(msg+'/answer')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')
    yield from resp.send_str('ask')

    assert resp.get_extra_info('socket') is not None

    data = yield from resp.receive_str()
    assert data == 'ask/answer'
    yield from resp.close()

    assert resp.get_extra_info('socket') is None


@asyncio.coroutine
def test_send_recv_bytes_bad_type(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_str()
        yield from ws.send_str(msg+'/answer')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')
    yield from resp.send_str('ask')

    with pytest.raises(TypeError):
        yield from resp.receive_bytes()
    yield from resp.close()


@asyncio.coroutine
def test_send_recv_bytes(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        yield from ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')

    yield from resp.send_bytes(b'ask')

    data = yield from resp.receive_bytes()
    assert data == b'ask/answer'

    yield from resp.close()


@asyncio.coroutine
def test_send_recv_text_bad_type(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        yield from ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')

    yield from resp.send_bytes(b'ask')

    with pytest.raises(TypeError):
        yield from resp.receive_str()

    yield from resp.close()


@asyncio.coroutine
def test_send_recv_json(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        yield from ws.send_json({'response': data['request']})
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')
    payload = {'request': 'test'}
    resp.send_json(payload)

    data = yield from resp.receive_json()
    assert data['response'] == payload['request']
    yield from resp.close()


@asyncio.coroutine
def test_ping_pong(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.ping()
        yield from ws.send_bytes(msg+b'/answer')
        try:
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')

    resp.ping()
    yield from resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert msg.data == b'ask/answer'

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    yield from resp.close()
    yield from closed


@asyncio.coroutine
def test_ping_pong_manual(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        ws.ping()
        yield from ws.send_bytes(msg+b'/answer')
        try:
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', autoping=False)

    resp.ping()
    yield from resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.PONG

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.PING
    resp.pong()

    msg = yield from resp.receive()
    assert msg.data == b'ask/answer'

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE

    yield from closed


@asyncio.coroutine
def test_close(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_bytes()
        yield from ws.send_str('test')

        yield from ws.receive()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')

    yield from resp.send_bytes(b'ask')

    closed = yield from resp.close()
    assert closed
    assert resp.closed
    assert resp.close_code == 1000

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED


@asyncio.coroutine
def test_concurrent_close(loop, test_client):
    client_ws = None

    @asyncio.coroutine
    def handler(request):
        nonlocal client_ws
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_bytes()
        yield from ws.send_str('test')

        yield from client_ws.close()

        msg = yield from ws.receive()
        assert msg.type == aiohttp.WSMsgType.CLOSE
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    ws = client_ws = yield from client.ws_connect('/')

    yield from ws.send_bytes(b'ask')

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSING

    yield from asyncio.sleep(0.01, loop=loop)
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED


@asyncio.coroutine
def test_close_from_server(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        try:
            yield from ws.receive_bytes()
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')

    yield from resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert resp.closed

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSED

    yield from closed


@asyncio.coroutine
def test_close_manual(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_bytes()
        yield from ws.send_str('test')

        try:
            yield from ws.close()
        finally:
            closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', autoclose=False)
    yield from resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.data == 'test'

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''
    assert not resp.closed

    yield from resp.close()
    yield from closed
    assert resp.closed


@asyncio.coroutine
def test_close_timeout(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive_bytes()
        yield from ws.send_str('test')
        yield from asyncio.sleep(1, loop=loop)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', timeout=0.2, autoclose=False)

    yield from resp.send_bytes(b'ask')

    msg = yield from resp.receive()
    assert msg.data == 'test'
    assert msg.type == aiohttp.WSMsgType.TEXT

    msg = yield from resp.close()
    assert resp.closed
    assert isinstance(resp.exception(), asyncio.TimeoutError)


@asyncio.coroutine
def test_close_cancel(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive_bytes()
        yield from ws.send_str('test')
        yield from asyncio.sleep(10, loop=loop)

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', autoclose=False)

    yield from resp.send_bytes(b'ask')

    text = yield from resp.receive()
    assert text.data == 'test'

    t = loop.create_task(resp.close())
    yield from asyncio.sleep(0.1, loop=loop)
    t.cancel()
    yield from asyncio.sleep(0.1, loop=loop)
    assert resp.closed
    assert resp.exception() is None


@asyncio.coroutine
def test_override_default_headers(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        assert request.headers[hdrs.SEC_WEBSOCKET_VERSION] == '8'
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.send_str('answer')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    headers = {hdrs.SEC_WEBSOCKET_VERSION: '8'}
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', headers=headers)
    msg = yield from resp.receive()
    assert msg.data == 'answer'
    yield from resp.close()


@asyncio.coroutine
def test_additional_headers(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        assert request.headers['x-hdr'] == 'xtra'
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.send_str('answer')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', headers={'x-hdr': 'xtra'})
    msg = yield from resp.receive()
    assert msg.data == 'answer'
    yield from resp.close()


@asyncio.coroutine
def test_recv_protocol_error(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_str()
        ws._writer.writer.write(b'01234' * 100)
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')
    yield from resp.send_str('ask')

    msg = yield from resp.receive()
    assert msg.type == aiohttp.WSMsgType.ERROR
    assert type(msg.data) is aiohttp.WebSocketError
    assert msg.data.args[0] == 'Received frame with non-zero reserved bits'
    assert msg.extra is None
    yield from resp.close()


@asyncio.coroutine
def test_recv_timeout(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive_str()

        yield from asyncio.sleep(0.1, loop=request.app.loop)

        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')
    yield from resp.send_str('ask')

    with pytest.raises(asyncio.TimeoutError):
        with aiohttp.Timeout(0.01, loop=app.loop):
            yield from resp.receive()

    yield from resp.close()


@asyncio.coroutine
def test_receive_timeout(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive()
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', receive_timeout=0.1)

    with pytest.raises(asyncio.TimeoutError):
        yield from resp.receive(0.05)

    yield from resp.close()


@asyncio.coroutine
def test_custom_receive_timeout(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive()
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = yield from test_client(app)
    resp = yield from client.ws_connect('/')

    with pytest.raises(asyncio.TimeoutError):
        yield from resp.receive(0.05)

    yield from resp.close()


@asyncio.coroutine
def test_heartbeat(loop, test_client, ceil):
    ping_received = False

    @asyncio.coroutine
    def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        yield from ws.prepare(request)
        msg = yield from ws.receive()
        if msg.type == aiohttp.WSMsgType.ping:
            ping_received = True
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', heartbeat=0.01)

    yield from resp.receive()
    yield from resp.close()

    assert ping_received


@asyncio.coroutine
def test_heartbeat_no_pong(loop, test_client, ceil):
    ping_received = False

    @asyncio.coroutine
    def handler(request):
        nonlocal ping_received
        ws = web.WebSocketResponse(autoping=False)
        yield from ws.prepare(request)
        msg = yield from ws.receive()
        if msg.type == aiohttp.WSMsgType.ping:
            ping_received = True
        yield from ws.receive()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)

    client = yield from test_client(app)
    resp = yield from client.ws_connect('/', heartbeat=0.05)

    yield from resp.receive()
    yield from resp.receive()

    assert ping_received
