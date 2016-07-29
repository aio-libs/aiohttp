import asyncio
import unittest
from unittest import mock
import pytest
from aiohttp import CIMultiDict, helpers
from aiohttp.web import (
    MsgType, Request, WebSocketResponse, HTTPMethodNotAllowed, HTTPBadRequest)
from aiohttp.protocol import RawRequestMessage, HttpVersion11
from aiohttp import errors, signals, websocket
from aiohttp.test_utils import make_mocked_request


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
def make_request(app, writer):
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
                                   app=app, writer=writer)

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
        return websocket.Message(websocket.MSG_BINARY, b'data', b'')

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
        return websocket.Message(websocket.MSG_TEXT, 'data', b'')

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


class TestWebWebSocket(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=None, protocols=False):
        self.app = mock.Mock()
        self.app._debug = False
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

        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    [(k.encode('utf-8'), v.encode('utf-8'))
                                     for k, v in headers.items()],
                                    False, False)
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.reader = mock.Mock()
        self.writer = mock.Mock()
        self.app.loop = self.loop
        self.app.on_response_prepare = signals.Signal(self.app)
        req = Request(self.app, message, self.payload,
                      self.transport, self.reader, self.writer)
        return req

    def test_receive_exc_in_reader(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))

        exc = ValueError()
        res = helpers.create_future(self.loop)
        res.set_exception(exc)
        ws._reader.read.return_value = res

        @asyncio.coroutine
        def go():
            msg = yield from ws.receive()
            self.assertTrue(msg.tp, MsgType.error)
            self.assertIs(msg.data, exc)
            self.assertIs(ws.exception(), exc)

        self.loop.run_until_complete(go())

    def test_receive_cancelled(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))

        res = helpers.create_future(self.loop)
        res.set_exception(asyncio.CancelledError())
        ws._reader.read.return_value = res

        self.assertRaises(
            asyncio.CancelledError,
            self.loop.run_until_complete, ws.receive())

    def test_receive_timeouterror(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))

        res = helpers.create_future(self.loop)
        res.set_exception(asyncio.TimeoutError())
        ws._reader.read.return_value = res

        self.assertRaises(
            asyncio.TimeoutError,
            self.loop.run_until_complete, ws.receive())

    def test_receive_client_disconnected(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))

        exc = errors.ClientDisconnectedError()
        res = helpers.create_future(self.loop)
        res.set_exception(exc)
        ws._reader.read.return_value = res

        @asyncio.coroutine
        def go():
            msg = yield from ws.receive()
            self.assertTrue(ws.closed)
            self.assertTrue(msg.tp, MsgType.close)
            self.assertIs(msg.data, None)
            self.assertIs(ws.exception(), None)

        self.loop.run_until_complete(go())

    def test_multiple_receive_on_close_connection(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))
        self.loop.run_until_complete(ws.close())
        self.loop.run_until_complete(ws.receive())
        self.loop.run_until_complete(ws.receive())
        self.loop.run_until_complete(ws.receive())
        self.loop.run_until_complete(ws.receive())
        self.assertRaises(
            RuntimeError, self.loop.run_until_complete, ws.receive())

    def test_concurrent_receive(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))
        ws._waiting = True

        self.assertRaises(
            RuntimeError, self.loop.run_until_complete, ws.receive())

    def test_close_exc(self):
        req = self.make_request('GET', '/')
        reader = self.reader.set_parser.return_value = mock.Mock()

        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))

        exc = ValueError()
        reader.read.return_value = helpers.create_future(self.loop)
        reader.read.return_value.set_exception(exc)

        self.loop.run_until_complete(ws.close())
        self.assertTrue(ws.closed)
        self.assertIs(ws.exception(), exc)

        ws._closed = False
        reader.read.return_value = helpers.create_future(self.loop)
        reader.read.return_value.set_exception(asyncio.CancelledError())
        self.assertRaises(asyncio.CancelledError,
                          self.loop.run_until_complete, ws.close())
        self.assertEqual(ws.close_code, 1006)

    def test_close_exc2(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.loop.run_until_complete(ws.prepare(req))

        exc = ValueError()
        self.writer.close.side_effect = exc
        ws._writer = self.writer

        self.loop.run_until_complete(ws.close())
        self.assertTrue(ws.closed)
        self.assertIs(ws.exception(), exc)

        ws._closed = False
        self.writer.close.side_effect = asyncio.CancelledError()
        self.assertRaises(asyncio.CancelledError,
                          self.loop.run_until_complete, ws.close())

    def test_start_twice_idempotent(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        with self.assertWarns(DeprecationWarning):
            impl1 = ws.start(req)
            impl2 = ws.start(req)
            self.assertIs(impl1, impl2)

    def test_can_start_ok(self):
        req = self.make_request('GET', '/', protocols=True)
        ws = WebSocketResponse(protocols=('chat',))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual((True, 'chat'), ws.can_start(req))
