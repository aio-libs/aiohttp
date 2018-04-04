import asyncio
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp import WSMessage, WSMsgType, signals
from aiohttp.log import ws_logger
from aiohttp.streams import EofStream
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web import HTTPBadRequest, HTTPMethodNotAllowed, WebSocketResponse
from aiohttp.web_ws import WS_CLOSED_MESSAGE, WebSocketReady


@pytest.fixture
def app(loop):
    ret = mock.Mock()
    ret.loop = loop
    ret._debug = False
    ret.on_response_prepare = signals.Signal(ret)
    ret.on_response_prepare.freeze()
    return ret


@pytest.fixture
def protocol():
    ret = mock.Mock()
    ret.set_parser.return_value = ret
    return ret


@pytest.fixture
def make_request(app, protocol):
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
            app=app, protocol=protocol,
            loop=app.loop)

    return maker


async def test_nonstarted_ping():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.ping()


async def test_nonstarted_pong():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.pong()


async def test_nonstarted_send_str():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_str('string')


async def test_nonstarted_send_bytes():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_bytes(b'bytes')


async def test_nonstarted_send_json():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.send_json({'type': 'json'})


async def test_nonstarted_close():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.close()


async def test_nonstarted_receive_str():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_str()


async def test_nonstarted_receive_bytes():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_bytes()


async def test_nonstarted_receive_json():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.receive_json()


async def test_receive_str_nonstring(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    async def receive():
        return WSMessage(WSMsgType.BINARY, b'data', b'')

    ws.receive = receive

    with pytest.raises(TypeError):
        await ws.receive_str()


async def test_receive_bytes_nonsbytes(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    async def receive():
        return WSMessage(WSMsgType.TEXT, 'data', b'')

    ws.receive = receive

    with pytest.raises(TypeError):
        await ws.receive_bytes()


async def test_send_str_nonstring(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_str(b'bytes')


async def test_send_bytes_nonbytes(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_bytes('string')


async def test_send_json_nonjson(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(TypeError):
        await ws.send_json(set())


async def test_write_non_prepared():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.write(b'data')


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
    assert WebSocketReady(True, 'chat') == ws.can_prepare(req)


def test_can_prepare_unknown_protocol(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    assert WebSocketReady(True, None) == ws.can_prepare(req)


def test_can_prepare_invalid_method(make_request):
    req = make_request('POST', '/')
    ws = WebSocketResponse()
    assert WebSocketReady(False, None) == ws.can_prepare(req)


def test_can_prepare_without_upgrade(make_request):
    req = make_request('GET', '/',
                       headers=CIMultiDict({}))
    ws = WebSocketResponse()
    assert WebSocketReady(False, None) == ws.can_prepare(req)


async def test_can_prepare_started(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    with pytest.raises(RuntimeError) as ctx:
        ws.can_prepare(req)

    assert 'Already started' in str(ctx.value)


def test_closed_after_ctor():
    ws = WebSocketResponse()
    assert not ws.closed
    assert ws.close_code is None


async def test_send_str_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    mocker.spy(ws_logger, 'warning')
    await ws.send_str('string')
    assert ws_logger.warning.called


async def test_send_bytes_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    mocker.spy(ws_logger, 'warning')
    await ws.send_bytes(b'bytes')
    assert ws_logger.warning.called


async def test_send_json_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    mocker.spy(ws_logger, 'warning')
    await ws.send_json({'type': 'json'})
    assert ws_logger.warning.called


async def test_ping_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    mocker.spy(ws_logger, 'warning')
    await ws.ping()
    assert ws_logger.warning.called


async def test_pong_closed(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    mocker.spy(ws_logger, 'warning')
    await ws.pong()
    assert ws_logger.warning.called


async def test_close_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    assert (await ws.close(code=1, message='message1'))
    assert ws.closed
    assert not (await ws.close(code=2, message='message2'))


async def test_prepare_invalid_method(make_request):
    req = make_request('POST', '/')
    ws = WebSocketResponse()
    with pytest.raises(HTTPMethodNotAllowed):
        await ws.prepare(req)


async def test_prepare_without_upgrade(make_request):
    req = make_request('GET', '/',
                       headers=CIMultiDict({}))
    ws = WebSocketResponse()
    with pytest.raises(HTTPBadRequest):
        await ws.prepare(req)


async def test_wait_closed_before_start():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.close()


async def test_write_eof_not_started():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        await ws.write_eof()


async def test_write_eof_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    await ws.write_eof()
    await ws.write_eof()
    await ws.write_eof()


async def test_receive_eofstream_in_reader(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = EofStream()
    res = loop.create_future()
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.CLOSED
    assert ws.closed


async def test_receive_exc_in_reader(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = ValueError()
    res = loop.create_future()
    res.set_exception(exc)
    ws._reader.read = make_mocked_coro(res)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    msg = await ws.receive()
    assert msg.type == WSMsgType.ERROR
    assert msg.data is exc
    assert ws.exception() is exc


async def test_receive_cancelled(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    res = loop.create_future()
    res.set_exception(asyncio.CancelledError())
    ws._reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.CancelledError):
        await ws.receive()


async def test_receive_timeouterror(make_request, loop):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    res = loop.create_future()
    res.set_exception(asyncio.TimeoutError())
    ws._reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.TimeoutError):
        await ws.receive()


async def test_multiple_receive_on_close_connection(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._reader.feed_data(WS_CLOSED_MESSAGE, 0)
    await ws.close()

    await ws.receive()
    await ws.receive()
    await ws.receive()
    await ws.receive()

    with pytest.raises(RuntimeError):
        await ws.receive()


async def test_concurrent_receive(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    ws._waiting = True

    with pytest.raises(RuntimeError):
        await ws.receive()


async def test_close_exc(make_request, loop, mocker):
    req = make_request('GET', '/')

    ws = WebSocketResponse()
    await ws.prepare(req)

    ws._reader = mock.Mock()
    exc = ValueError()
    ws._reader.read.return_value = loop.create_future()
    ws._reader.read.return_value.set_exception(exc)
    ws._payload_writer.drain = mock.Mock()
    ws._payload_writer.drain.return_value = loop.create_future()
    ws._payload_writer.drain.return_value.set_result(True)

    await ws.close()
    assert ws.closed
    assert ws.exception() is exc

    ws._closed = False
    ws._reader.read.return_value = loop.create_future()
    ws._reader.read.return_value.set_exception(asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await ws.close()
    assert ws.close_code == 1006


async def test_close_exc2(make_request):

    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)

    exc = ValueError()
    ws._writer = mock.Mock()
    ws._writer.close.side_effect = exc
    await ws.close()
    assert ws.closed
    assert ws.exception() is exc

    ws._closed = False
    ws._writer.close.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await ws.close()


async def test_prepare_twice_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()

    impl1 = await ws.prepare(req)
    impl2 = await ws.prepare(req)
    assert impl1 is impl2


async def test_send_with_per_message_deflate(make_request, mocker):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    await ws.prepare(req)
    writer_send = ws._writer.send = make_mocked_coro()

    await ws.send_str('string', compress=15)
    writer_send.assert_called_with('string', binary=False, compress=15)

    await ws.send_bytes(b'bytes', compress=0)
    writer_send.assert_called_with(b'bytes', binary=True, compress=0)

    await ws.send_json('[{}]', compress=9)
    writer_send.assert_called_with('"[{}]"', binary=False, compress=9)
