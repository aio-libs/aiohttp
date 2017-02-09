"""HTTP websocket server functional tests"""

import asyncio

import pytest

import aiohttp
from aiohttp import helpers, web
from aiohttp._ws_impl import WSMsgType


@asyncio.coroutine
def test_websocket_json(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)
        msg = yield from ws.receive()

        msg_json = msg.json()
        answer = msg_json['test']
        ws.send_str(answer)

        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    ws.send_str(payload)

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
            ws.send_str('ValueError was raised')
        else:
            raise Exception('No Exception')
        finally:
            yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    payload = 'NOT A VALID JSON STRING'
    ws.send_str(payload)

    data = yield from ws.receive_str()
    assert 'ValueError was raised' in data


@asyncio.coroutine
def test_websocket_send_json(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        data = yield from ws.receive_json()
        ws.send_json(data)

        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    ws.send_json({'test': expected_value})

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

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    ws.send_json({'test': expected_value})

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
        ws.send_str(answer)

        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    expected_value = 'value'
    payload = '{"test": "%s"}' % expected_value
    ws.send_str(payload)

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
        ws.send_str(msg+'/answer')
        yield from ws.close()
        closed.set_result(1)
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    ws.send_str('ask')
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
        ws.send_bytes(msg+b'/answer')
        yield from ws.close()
        closed.set_result(1)
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    ws.send_bytes(b'ask')
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
        ws.send_json({'response': data['request']})
        yield from ws.close()
        closed.set_result(1)
        return ws

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')

    ws.send_str('{"request": "test"}')
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
        ws.send_str('reply')
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

    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    ws.send_str('request')
    assert 'reply' == (yield from ws.receive_str())

    # The server closes here.  Then the client sends bogus messages with an
    # internval shorter than server-side close timeout, to make the server
    # hanging indefinitely.
    yield from asyncio.sleep(0.08, loop=loop)
    msg = yield from ws._reader.read()
    assert msg.type == WSMsgType.CLOSE
    ws.send_str('hang')
    yield from asyncio.sleep(0.08, loop=loop)
    ws.send_str('hang')
    yield from asyncio.sleep(0.08, loop=loop)
    ws.send_str('hang')
    yield from asyncio.sleep(0.08, loop=loop)
    ws.send_str('hang')
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

    app = web.Application(loop=loop)
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

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False, autoping=False)
    ws.ping()
    ws.send_str('ask')

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

    app = web.Application(loop=loop)
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

    app = web.Application(loop=loop)
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

    app = web.Application(loop=loop)
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

    app = web.Application(loop=loop)
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
        assert 'bar' == ws.protocol
        closed.set_result(None)
        return ws

    app = web.Application(loop=loop)
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

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False,
                                      protocols=('eggs', 'bar'))

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSE
    yield from ws.close()
    yield from closed


@asyncio.coroutine
def test_client_close_handshake(loop, test_client):

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

    app = web.Application(loop=loop)
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

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/', autoclose=False, autoping=False,
                                      protocols=('eggs', 'bar'))

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.CLOSE

    ws.send_str('text')
    ws.send_bytes(b'bytes')
    ws.ping()

    yield from ws.close()
    yield from closed


@asyncio.coroutine
def test_receive_msg(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse()
        yield from ws.prepare(request)

        with pytest.warns(DeprecationWarning):
            msg = yield from ws.receive_msg()
            assert msg.data == b'data'
        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    ws.send_bytes(b'data')
    yield from ws.close()


@asyncio.coroutine
def test_receive_timeout(loop, test_client):
    raised = False

    @asyncio.coroutine
    def handler(request):
        ws = web.WebSocketResponse(receive_timeout=0.1)
        yield from ws.prepare(request)

        ws._time_service._interval = 0.05
        try:
            yield from ws.receive()
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
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

        ws._time_service._interval = 0.05
        try:
            yield from ws.receive(0.1)
        except asyncio.TimeoutError:
            nonlocal raised
            raised = True

        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    ws = yield from client.ws_connect('/')
    yield from ws.receive()
    yield from ws.close()
    assert raised


@asyncio.coroutine
def test_heartbeat(loop, test_client):
    @asyncio.coroutine
    def handler(request):
        request._time_service._interval = 0.1

        ws = web.WebSocketResponse(heartbeat=0.05)
        yield from ws.prepare(request)
        yield from ws.receive()
        yield from ws.close()
        return ws

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    ws = yield from client.ws_connect('/', autoping=False)
    msg = yield from ws.receive()

    assert msg.type == aiohttp.WSMsgType.ping

    yield from ws.close()


@asyncio.coroutine
def test_heartbeat_no_pong(loop, test_client):
    cancelled = False

    @asyncio.coroutine
    def handler(request):
        nonlocal cancelled
        request._time_service._interval = 0.1
        request._time_service._on_cb()

        ws = web.WebSocketResponse(heartbeat=0.05)
        yield from ws.prepare(request)

        try:
            yield from ws.receive()
        except asyncio.CancelledError:
            cancelled = True

        return ws

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)

    client = yield from test_client(app)
    ws = yield from client.ws_connect('/', autoping=False)
    msg = yield from ws.receive()
    assert msg.type == aiohttp.WSMsgType.ping
    yield from ws.receive()

    assert cancelled
