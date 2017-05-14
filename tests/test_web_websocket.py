import asyncio
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import WSMessage, WSMsgType, helpers, signals
from aiohttp.log import ws_logger
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web import HTTPBadRequest, HTTPMethodNotAllowed, WebSocketResponse
from aiohttp.web_ws import WS_CLOSED_MESSAGE, WebSocketReady


@pytest.fixture
def app(loop):
    ret = mock.Mock()
    ret.loop = loop
    ret._debug = False
    ret.on_response_prepare = signals.Signal(ret)
    return ret


@pytest.fixture
def writer():
    writer = mock.Mock()
    writer.drain.return_value = ()
    writer.write_eof.return_value = ()
    return writer


@pytest.fixture
def protocol():
    ret = mock.Mock()
    ret.set_parser.return_value = ret
    return ret


@pytest.fixture
def make_request(app, protocol, writer):
    def maker(method, path, headers=None, protocols=False):
        if headers is None:
            headers = CIMultiDict(
                {'HOST': 'server.example.com',
                 'UPGRADE': 'websocket',
                 'CONNECTION': 'Upgrade',
                 'SEC-WEBSOCKET-KEY': 'dGhlIHNhbXBsZSBub25jZQ==',
                 'ORIGIN': 'http://example.com',
                 'SEC-WEBSOCKET-VERSION': '13'})
        if protocols:
            headers['SEC-WEBSOCKET-PROTOCOL'] = 'chat, superchat'

        return make_mocked_request(
            method, path, headers,
            app=app, protocol=protocol, payload_writer=writer)

    return maker


def test_nonstarted_ping():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        ws.ping()


def test_nonstarted_pong():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        ws.pong()


def test_nonstarted_send_str():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        ws.send_str('string')


def test_nonstarted_send_bytes():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        ws.send_bytes(b'bytes')


def test_nonstarted_send_json():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        ws.send_json({'type': 'json'})


@asyncio.coroutine
def test_nonstarted_close():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.close()


@asyncio.coroutine
def test_nonstarted_receive_str():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.receive_str()


@asyncio.coroutine
def test_nonstarted_receive_bytes():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.receive_bytes()


@asyncio.coroutine
def test_nonstarted_receive_json():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.receive_json()


@asyncio.coroutine
def test_receive_str_nonstring(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    @asyncio.coroutine
    def receive():
        return WSMessage(WSMsgType.BINARY, b'data', b'')

    ws.receive = receive

    with pytest.raises(TypeError):
        yield from ws.receive_str()


@asyncio.coroutine
def test_receive_bytes_nonsbytes(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    @asyncio.coroutine
    def receive():
        return WSMessage(WSMsgType.TEXT, 'data', b'')

    ws.receive = receive

    with pytest.raises(TypeError):
        yield from ws.receive_bytes()


@asyncio.coroutine
def test_send_str_nonstring(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    with pytest.raises(TypeError):
        ws.send_str(b'bytes')


@asyncio.coroutine
def test_send_bytes_nonbytes(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    with pytest.raises(TypeError):
        ws.send_bytes('string')


@asyncio.coroutine
def test_send_json_nonjson(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    with pytest.raises(TypeError):
        ws.send_json(set())


def test_write_non_prepared():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        ws.write(b'data')


def test_websocket_ready():
    websocket_ready = WebSocketReady(True, 'chat')
    assert websocket_ready.ok is True
    assert websocket_ready.protocol == 'chat'


def test_websocket_not_ready():
    websocket_ready = WebSocketReady(False, None)
    assert websocket_ready.ok is False
    assert websocket_ready.protocol is None


def test_websocket_ready_unknown_protocol():
    websocket_ready = WebSocketReady(True, None)
    assert websocket_ready.ok is True
    assert websocket_ready.protocol is None


def test_bool_websocket_ready():
    websocket_ready = WebSocketReady(True, None)
    assert bool(websocket_ready) is True


def test_bool_websocket_not_ready():
    websocket_ready = WebSocketReady(False, None)
    assert bool(websocket_ready) is False


def test_can_prepare_ok(make_request):
    req = make_request('GET', '/', protocols=True)
    ws = WebSocketResponse(protocols=('chat',))
    assert(True, 'chat') == ws.can_prepare(req)


def test_can_prepare_unknown_protocol(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    assert (True, None) == ws.can_prepare(req)


def test_can_prepare_invalid_method(make_request):
    req = make_request('POST', '/')
    ws = WebSocketResponse()
    assert (False, None) == ws.can_prepare(req)


def test_can_prepare_without_upgrade(make_request):
    req = make_request('GET', '/',
                       headers=CIMultiDict({}))
    ws = WebSocketResponse()
    assert (False, None) == ws.can_prepare(req)


@asyncio.coroutine
def test_can_prepare_started(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    with pytest.raises(RuntimeError) as ctx:
        ws.can_prepare(req)

    assert 'Already started' in str(ctx.value)


def test_closed_after_ctor():
    ws = WebSocketResponse()
    assert not ws.closed
    assert ws.close_code is None


@asyncio.coroutine
def test_send_str_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    mocker.spy(ws_logger, 'warning')
    ws.send_str('string')
    assert ws_logger.warning.called


@asyncio.coroutine
def test_send_bytes_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    mocker.spy(ws_logger, 'warning')
    ws.send_bytes(b'bytes')
    assert ws_logger.warning.called


@asyncio.coroutine
def test_send_json_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    mocker.spy(ws_logger, 'warning')
    ws.send_json({'type': 'json'})
    assert ws_logger.warning.called


@asyncio.coroutine
def test_ping_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    mocker.spy(ws_logger, 'warning')
    ws.ping()
    assert ws_logger.warning.called


@asyncio.coroutine
def test_pong_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    mocker.spy(ws_logger, 'warning')
    ws.pong()
    assert ws_logger.warning.called


@asyncio.coroutine
def test_close_idempotent(make_request, writer):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    assert (yield from ws.close(code=1, message='message1'))
    assert ws.closed
    assert not (yield from ws.close(code=2, message='message2'))


@asyncio.coroutine
def test_prepare_invalid_method(make_request):
    req = make_request('POST', '/')
    ws = WebSocketResponse()
    with pytest.raises(HTTPMethodNotAllowed):
        yield from ws.prepare(req)


@asyncio.coroutine
def test_prepare_without_upgrade(make_request):
    req = make_request('GET', '/',
                       headers=CIMultiDict({}))
    ws = WebSocketResponse()
    with pytest.raises(HTTPBadRequest):
        yield from ws.prepare(req)


@asyncio.coroutine
def test_wait_closed_before_start():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.close()


@asyncio.coroutine
def test_write_eof_not_started():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.write_eof()


@asyncio.coroutine
def test_write_eof_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    yield from ws.write_eof()
    yield from ws.write_eof()
    yield from ws.write_eof()


@asyncio.coroutine
def test_receive_exc_in_reader(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    ws._reader = mock.Mock()
    exc = ValueError()
    res = helpers.create_future(loop)
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = helpers.create_future(loop)
    ws._payload_writer.drain.return_value.set_result(True)

    msg = yield from ws.receive()
    assert msg.type == WSMsgType.ERROR
    assert msg.type is msg.tp
    assert msg.data is exc
    assert ws.exception() is exc


@asyncio.coroutine
def test_receive_cancelled(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    ws._reader = mock.Mock()
    res = helpers.create_future(loop)
    res.set_exception(asyncio.CancelledError())
    ws._reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.CancelledError):
        yield from ws.receive()


@asyncio.coroutine
def test_receive_timeouterror(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    ws._reader = mock.Mock()
    res = helpers.create_future(loop)
    res.set_exception(asyncio.TimeoutError())
    ws._reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.TimeoutError):
        yield from ws.receive()


@asyncio.coroutine
def test_multiple_receive_on_close_connection(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    yield from ws.close()

    yield from ws.receive()
    yield from ws.receive()
    yield from ws.receive()
    yield from ws.receive()

    with pytest.raises(RuntimeError):
        yield from ws.receive()


@asyncio.coroutine
def test_concurrent_receive(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._waiting = True

    with pytest.raises(RuntimeError):
        yield from ws.receive()


@asyncio.coroutine
def test_close_exc(make_request, loop, mocker):
    req = make_request('GET', '/')

    ws = WebSocketResponse()
    yield from ws.prepare(req)

    ws._reader = mock.Mock()
    exc = ValueError()
    ws._reader.read.return_value = helpers.create_future(loop)
    ws._reader.read.return_value.set_exception(exc)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = helpers.create_future(loop)
    ws._payload_writer.drain.return_value.set_result(True)

    yield from ws.close()
    assert ws.closed
    assert ws.exception() is exc

    ws._closed = False
    ws._reader.read.return_value = helpers.create_future(loop)
    ws._reader.read.return_value.set_exception(asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        yield from ws.close()
    assert ws.close_code == 1006


@asyncio.coroutine
def test_close_exc2(make_request):

    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    exc = ValueError()
    ws._writer = mock.Mock()
    ws._writer.close.side_effect = exc
    yield from ws.close()
    assert ws.closed
    assert ws.exception() is exc

    ws._closed = False
    ws._writer.close.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        yield from ws.close()


@asyncio.coroutine
def test_prepare_twice_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()

    impl1 = yield from ws.prepare(req)
    impl2 = yield from ws.prepare(req)
    assert impl1 is impl2
