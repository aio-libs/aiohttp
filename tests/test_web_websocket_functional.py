"""HTTP websocket server functional tests"""

import asyncio

import pytest

import aiohttp
from aiohttp import helpers, web
from aiohttp.http import WSMsgType


@pytest.fixture
def ceil(mocker):
    def ceil(val):
        return val

    mocker.patch('aiohttp.helpers.ceil').side_effect = ceil


@asyncio.coroutine
def test_websocket_can_prepare(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.HTTPUpgradeRequired()

        return web.HTTPOk()

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert resp.status == 426


@asyncio.coroutine
def test_websocket_json(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.HTTPUpgradeRequired()

        yield from ws.prepare(request)
        msg = yield from ws.receive()

        msg_json = msg.json()
        answer = msg_json['test']
        yield from ws.send_str(answer)

        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    yield from ws.send_str(payload)

    resp = yield from ws.receive()
    assert resp.data == expected_value


@asyncio.coroutine
def test_websocket_json_invalid_message(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        try:
            yield from ws.receive_json()
        except ValueError:
            yield from ws.send_str('ValueError was raised')
        else:
            raise Exception('No Exception')
        finally:
            yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    payload = 'NOT A VALID JSON STRING'
    yield from ws.send_str(payload)

    data = yield from ws.receive_str()
    assert 'ValueError was raised' in data


@asyncio.coroutine
def test_websocket_send_json(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        yield from ws.send_json(data)

        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    yield from ws.send_json({'test': expected_value})

    data = yield from ws.receive_json()
    assert data['test'] == expected_value


@asyncio.coroutine
def test_websocket_send_drain(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        ws._writer._limit = 1

        data = yield from ws.receive_json()
        drain = ws.send_json(data)
        assert drain

        yield from drain
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    yield from ws.send_json({'test': expected_value})

    data = yield from ws.receive_json()
    assert data['test'] == expected_value


@asyncio.coroutine
def test_websocket_receive_json(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        answer = data['test']
        yield from ws.send_str(answer)

        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    yield from ws.send_str(payload)

    resp = yield from ws.receive()
    assert resp.data == expected_value


@asyncio.coroutine
def test_send_recv_text(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        msg = yield from ws.receive_str()
        yield from ws.send_str(msg+'/answer')
        yield from ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    yield from ws.send_str('ask')
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert 'ask/answer' == msg.data

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    assert ws.closed
    assert ws.close_code == 1000

    yield from closed


@asyncio.coroutine
def test_send_recv_bytes(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        msg = yield from ws.receive_bytes()
        yield from ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    yield from ws.send_bytes(b'ask')
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.BINARY
    assert b'ask/answer' == msg.data

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    assert ws.closed
    assert ws.close_code == 1000

    yield from closed


@asyncio.coroutine
def test_send_recv_json(loop, test_client):
    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        data = yield from ws.receive_json()
        yield from ws.send_json({'response': data['request']})
        yield from ws.close()
        closed.set_result(1)
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')

    yield from ws.send_str('{"request": "test"}')
    msg = yield from ws.receive()
    data = msg.json()
    assert msg.type == aiohttp.WSMsgType.TEXT
    assert data['response'] == 'test'

    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.CLOSE
    assert msg.data == 1000
    assert msg.extra == ''

    yield from ws.close()

    yield from closed


@asyncio.coroutine
def test_close_timeout(loop, test_client):
    aborted = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(timeout=0.1)
        yield from ws.prepare(request)
        assert 'request' == (yield from ws.receive_str())
        yield from ws.send_str('reply')
        begin = ws._loop.time()
        assert (yield from ws.close())
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
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    yield from ws.send_str('request')
    assert 'reply' == (yield from ws.receive_str())

    # The server closes here.  Then the client sends bogus messages with an
    # internval shorter than server-side close timeout, to make the server
    # hanging indefinitely.
    yield from asyncio.sleep(0.08, loop=loop)
    msg = yield from ws._reader.read()
    assert msg.type == WSMsgType.CLOSE
    yield from ws.send_str('hang')

    # i am not sure what do we test here
    # under uvloop this code raises RuntimeError
    try:
        yield from asyncio.sleep(0.08, loop=loop)
        yield from ws.send_str('hang')
        yield from asyncio.sleep(0.08, loop=loop)
        yield from ws.send_str('hang')
        yield from asyncio.sleep(0.08, loop=loop)
        yield from ws.send_str('hang')
    except RuntimeError:
        pass

    yield from asyncio.sleep(0.08, loop=loop)
    assert (yield from aborted)

    yield from ws.close()


@asyncio.coroutine
def test_concurrent_close(loop, test_client):

    srv_ws = None

    @asyncio.coroutine
    def handler(request):
        nonlocal srv_ws
        ws = srv_ws = web.WebSocketResponse(
            autoclose=False, protocols=('foo', 'bar'))
        yield from ws.prepare(request)

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSING

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSING

        yield from asyncio.sleep(0, loop=loop)

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSED

        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False,
                                      protocols=('eggs', 'bar'))

    yield from srv_ws.close(code=1007)

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSE

    yield from asyncio.sleep(0, loop=loop)
    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSED


@asyncio.coroutine
def test_auto_pong_with_closing_by_peer(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        yield from ws.receive()

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == 1000
        assert msg.extra == 'exit message'
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False, autoping=False)
    ws.ping()
    yield from ws.send_str('ask')

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.PONG
    yield from ws.close(code=1000, message='exit message')
    yield from closed


@asyncio.coroutine
def test_ping(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        ws.ping('data')
        yield from ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoping=False)

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.PING
    assert msg.data == b'data'
    ws.pong()
    yield from ws.close()
    yield from closed


@asyncio.coroutine
def test_client_ping(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        yield from ws.receive()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoping=False)

    ws.ping('data')
    msg = yield from ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b'data'
    ws.pong()
    yield from ws.close()


@asyncio.coroutine
def test_pong(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(autoping=False)
        yield from ws.prepare(request)

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.PING
        ws.pong('data')

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert msg.data == 1000
        assert msg.extra == 'exit message'
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoping=False)

    ws.ping('data')
    msg = yield from ws.receive()
    assert msg.type == WSMsgType.PONG
    assert msg.data == b'data'

    yield from ws.close(code=1000, message='exit message')

    yield from closed


@asyncio.coroutine
def test_change_status(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        ws.set_status(200)
        assert 200 == ws.status
        yield from ws.prepare(request)
        assert 101 == ws.status
        yield from ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoping=False)

    yield from ws.close()
    yield from closed
    yield from ws.close()


@asyncio.coroutine
def test_handle_protocol(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(protocols=('foo', 'bar'))
        yield from ws.prepare(request)
        yield from ws.close()
        assert 'bar' == ws.ws_protocol
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', protocols=('eggs', 'bar'))

    yield from ws.close()
    yield from closed


@asyncio.coroutine
def test_server_close_handshake(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(protocols=('foo', 'bar'))
        yield from ws.prepare(request)
        yield from ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False,
                                      protocols=('eggs', 'bar'))

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSE
    yield from ws.close()
    yield from closed


@asyncio.coroutine
def test_client_close_handshake(loop, test_client, ceil):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(
            autoclose=False, protocols=('foo', 'bar'))
        yield from ws.prepare(request)

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSE
        assert not ws.closed
        yield from ws.close()
        assert ws.closed
        assert ws.close_code == 1007

        msg = yield from ws.receive()
        assert msg.type == WSMsgType.CLOSED

        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False,
                                      protocols=('eggs', 'bar'))

    yield from ws.close(code=1007)
    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSED
    yield from closed


@asyncio.coroutine
def test_server_close_handshake_server_eats_client_messages(loop, test_client):

    closed = helpers.create_future(loop)

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(protocols=('foo', 'bar'))
        yield from ws.prepare(request)
        yield from ws.close()
        closed.set_result(None)
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False, autoping=False,
                                      protocols=('eggs', 'bar'))

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSE

    yield from ws.send_str('text')
    yield from ws.send_bytes(b'bytes')
    ws.ping()

    yield from ws.close()
    yield from closed


@asyncio.coroutine
def test_receive_timeout(loop, test_client):
    raised = False

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(receive_timeout=0.1)
        yield from ws.prepare(request)

        try:
            yield from ws.receive()
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    yield from ws.receive()
    yield from ws.close()
    assert raised


@asyncio.coroutine
def test_custom_receive_timeout(loop, test_client):
    raised = False

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(receive_timeout=None)
        yield from ws.prepare(request)

        try:
            yield from ws.receive(0.1)
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    yield from ws.receive()
    yield from ws.close()
    assert raised


@asyncio.coroutine
def test_heartbeat(loop, test_client, ceil):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(heartbeat=0.05)
        yield from ws.prepare(request)
        yield from ws.receive()
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    ws = yield from client.ws_connect('/', autoping=False)
    msg = yield from ws.receive()

    assert msg.type == aiohttp.WSMsgType.ping

    yield from ws.close()


@asyncio.coroutine
def test_heartbeat_no_pong(loop, test_client, ceil):
    cancelled = False

    @asyncio.coroutine
    def handler(request):
        nonlocal cancelled

        ws = web.WebSocketResponse(heartbeat=0.05)
        yield from ws.prepare(request)

        try:
            yield from ws.receive()
        except asyncio.CancelledError:
            cancelled = True

        return ws

    app = web.Application()
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    ws = yield from client.ws_connect('/', autoping=False)
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.ping
    yield from ws.receive()

    assert cancelled


@asyncio.coroutine
def test_websocket_disable_keepalive(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        if not ws.can_prepare(request):
            return web.Response(text='OK')
        assert request.protocol._keepalive
        yield from ws.prepare(request)
        assert not request.protocol._keepalive
        assert not request.protocol._keepalive_handle

        yield from ws.send_str('OK')
        yield from ws.close()
        return ws

    app = web.Application()
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    txt = yield from resp.text()
    assert txt == 'OK'

    ws = yield from client.ws_connect('/')
    data = yield from ws.receive_str()
    assert data == 'OK'
