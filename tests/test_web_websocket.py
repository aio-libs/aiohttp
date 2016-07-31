import asyncio
from unittest import mock
import pytest
from aiohttp import CIMultiDict, helpers
from aiohttp.web import (WebSocketResponse, HTTPMethodNotAllowed,
                         HTTPBadRequest)
from aiohttp import errors, signals, Message, MsgType
from aiohttp.test_utils import make_mocked_request, make_mocked_coro


@pytest.fixture
def app(loop):
    ret = mock.Mock()
    ret.loop = loop
    ret._debug = False
    ret.on_response_prepare = signals.Signal(ret)
    return ret


@pytest.fixture
def writer():
    return mock.Mock()


@pytest.fixture
def reader():
    ret = mock.Mock()
    ret.set_parser.return_value = ret
    return ret


@pytest.fixture
def make_request(app, writer, reader):
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

        return make_mocked_request(method, path, headers,
                                   app=app, writer=writer, reader=reader)

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


@pytest.mark.run_loop
def test_nonstarted_close():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.close()


@pytest.mark.run_Loop
def test_nonstarted_receive_str():

    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.receive_str()


@pytest.mark.run_loop
def test_nonstarted_receive_bytes():

    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.receive_bytes()


@pytest.mark.run_loop
def test_nonstarted_receive_json():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.receive_json()


@pytest.mark.run_loop
def test_receive_str_nonstring(make_request):

    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    @asyncio.coroutine
    def receive():
        return Message(MsgType.binary, b'data', b'')

    ws.receive = receive

    with pytest.raises(TypeError):
        yield from ws.receive_str()


@pytest.mark.run_loop
def test_receive_bytes_nonsbytes(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    @asyncio.coroutine
    def receive():
        return Message(MsgType.text, 'data', b'')

    ws.receive = receive

    with pytest.raises(TypeError):
        yield from ws.receive_bytes()


@pytest.mark.run_loop
def test_send_str_nonstring(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    with pytest.raises(TypeError):
        ws.send_str(b'bytes')


@pytest.mark.run_loop
def test_send_bytes_nonbytes(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    with pytest.raises(TypeError):
        ws.send_bytes('string')


@pytest.mark.run_loop
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


@pytest.mark.run_loop
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


@pytest.mark.run_loop
def test_send_str_closed(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()
    with pytest.raises(RuntimeError):
        ws.send_str('string')


@pytest.mark.run_loop
def test_send_bytes_closed(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()
    with pytest.raises(RuntimeError):
        ws.send_bytes(b'bytes')


@pytest.mark.run_loop
def test_send_json_closed(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()
    with pytest.raises(RuntimeError):
        ws.send_json({'type': 'json'})


@pytest.mark.run_loop
def test_ping_closed(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()
    with pytest.raises(RuntimeError):
        ws.ping()


@pytest.mark.run_loop
def test_pong_closed(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()
    with pytest.raises(RuntimeError):
        ws.pong()


@pytest.mark.run_loop
def test_close_idempotent(make_request, writer):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    assert (yield from ws.close(code=1, message='message1'))
    assert ws.closed
    assert not (yield from ws.close(code=2, message='message2'))


@pytest.mark.run_loop
def test_start_invalid_method(make_request):
    req = make_request('POST', '/')
    ws = WebSocketResponse()
    with pytest.raises(HTTPMethodNotAllowed):
        yield from ws.prepare(req)


@pytest.mark.run_loop
def test_start_without_upgrade(make_request):
    req = make_request('GET', '/',
                       headers=CIMultiDict({}))
    ws = WebSocketResponse()
    with pytest.raises(HTTPBadRequest):
        yield from ws.prepare(req)


@pytest.mark.run_loop
def test_wait_closed_before_start():
    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.close()


@pytest.mark.run_loop
def test_write_eof_not_started():

    ws = WebSocketResponse()
    with pytest.raises(RuntimeError):
        yield from ws.write_eof()


@pytest.mark.run_loop
def test_write_eof_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()

    yield from ws.write_eof()
    yield from ws.write_eof()
    yield from ws.write_eof()


@pytest.mark.run_loop
def test_receive_exc_in_reader(make_request, loop, reader):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    exc = ValueError()
    res = helpers.create_future(loop)
    res.set_exception(exc)
    reader.read = make_mocked_coro(res)

    msg = yield from ws.receive()
    assert msg.tp == MsgType.error
    assert msg.data is exc
    assert ws.exception() is exc


@pytest.mark.run_loop
def test_receive_cancelled(make_request, loop, reader):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    res = helpers.create_future(loop)
    res.set_exception(asyncio.CancelledError())
    reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.CancelledError):
        yield from ws.receive()


@pytest.mark.run_loop
def test_receive_timeouterror(make_request, loop, reader):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    res = helpers.create_future(loop)
    res.set_exception(asyncio.TimeoutError())
    reader.read = make_mocked_coro(res)

    with pytest.raises(asyncio.TimeoutError):
        yield from ws.receive()


@pytest.mark.run_loop
def test_receive_client_disconnected(make_request, loop, reader):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)

    exc = errors.ClientDisconnectedError()
    res = helpers.create_future(loop)
    res.set_exception(exc)
    reader.read = make_mocked_coro(res)

    msg = yield from ws.receive()
    assert ws.closed
    assert msg.tp == MsgType.close
    assert msg.data is None
    assert ws.exception() is None


@pytest.mark.run_loop
def test_multiple_receive_on_close_connection(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    yield from ws.close()

    yield from ws.receive()
    yield from ws.receive()
    yield from ws.receive()
    yield from ws.receive()

    with pytest.raises(RuntimeError):
        yield from ws.receive()


@pytest.mark.run_loop
def test_concurrent_receive(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    yield from ws.prepare(req)
    ws._waiting = True

    with pytest.raises(RuntimeError):
        yield from ws.receive()


@pytest.mark.run_loop
def test_close_exc(make_request, reader, loop):
    req = make_request('GET', '/')

    ws = WebSocketResponse()
    yield from ws.prepare(req)

    exc = ValueError()
    reader.read.return_value = helpers.create_future(loop)
    reader.read.return_value.set_exception(exc)

    yield from ws.close()
    assert ws.closed
    assert ws.exception() is exc

    ws._closed = False
    reader.read.return_value = helpers.create_future(loop)
    reader.read.return_value.set_exception(asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        yield from ws.close()
    assert ws.close_code == 1006


@pytest.mark.run_loop
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


def test_start_twice_idempotent(make_request):
    req = make_request('GET', '/')
    ws = WebSocketResponse()
    with pytest.warns(DeprecationWarning):
        impl1 = ws.start(req)
        impl2 = ws.start(req)
        assert impl1 is impl2


def test_can_start_ok(make_request):
    req = make_request('GET', '/', protocols=True)
    ws = WebSocketResponse(protocols=('chat',))
    with pytest.warns(DeprecationWarning):
        assert (True, 'chat') == ws.can_start(req)
