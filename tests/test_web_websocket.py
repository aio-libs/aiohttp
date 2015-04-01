import asyncio
import unittest
from unittest import mock
from aiohttp import CIMultiDict
from aiohttp.web import (
    MsgType, Request, WebSocketResponse, HTTPMethodNotAllowed, HTTPBadRequest)
from aiohttp.protocol import RawRequestMessage, HttpVersion11
from aiohttp import errors, websocket


class TestWebWebSocket(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=None):
        self.app = mock.Mock()
        if headers is None:
            headers = CIMultiDict(
                {'HOST': 'server.example.com',
                 'UPGRADE': 'websocket',
                 'CONNECTION': 'Upgrade',
                 'SEC-WEBSOCKET-KEY': 'dGhlIHNhbXBsZSBub25jZQ==',
                 'ORIGIN': 'http://example.com',
                 'SEC-WEBSOCKET-PROTOCOL': 'chat, superchat',
                 'SEC-WEBSOCKET-VERSION': '13'})
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.reader = mock.Mock()
        self.writer = mock.Mock()
        self.app.loop = self.loop
        req = Request(self.app, message, self.payload,
                      self.transport, self.reader, self.writer)
        return req

    def test_nonstarted_ping(self):
        ws = WebSocketResponse()
        with self.assertRaises(RuntimeError):
            ws.ping()

    def test_nonstarted_pong(self):
        ws = WebSocketResponse()
        with self.assertRaises(RuntimeError):
            ws.pong()

    def test_nonstarted_send_str(self):
        ws = WebSocketResponse()
        with self.assertRaises(RuntimeError):
            ws.send_str('string')

    def test_nonstarted_send_bytes(self):
        ws = WebSocketResponse()
        with self.assertRaises(RuntimeError):
            ws.send_bytes(b'bytes')

    def test_nonstarted_close(self):
        ws = WebSocketResponse()
        with self.assertRaises(RuntimeError):
            self.loop.run_until_complete(ws.close())

    def test_nonstarted_receive_str(self):

        @asyncio.coroutine
        def go():
            ws = WebSocketResponse()
            with self.assertRaises(RuntimeError):
                yield from ws.receive_str()

        self.loop.run_until_complete(go())

    def test_nonstarted_receive_bytes(self):

        @asyncio.coroutine
        def go():
            ws = WebSocketResponse()
            with self.assertRaises(RuntimeError):
                yield from ws.receive_bytes()

        self.loop.run_until_complete(go())

    def test_receive_str_nonstring(self):

        @asyncio.coroutine
        def go():
            req = self.make_request('GET', '/')
            ws = WebSocketResponse()
            ws.start(req)

            @asyncio.coroutine
            def receive():
                return websocket.Message(websocket.MSG_BINARY, b'data', b'')

            ws.receive = receive

            with self.assertRaises(TypeError):
                yield from ws.receive_str()

        self.loop.run_until_complete(go())

    def test_receive_bytes_nonsbytes(self):

        @asyncio.coroutine
        def go():
            req = self.make_request('GET', '/')
            ws = WebSocketResponse()
            ws.start(req)

            @asyncio.coroutine
            def receive():
                return websocket.Message(websocket.MSG_TEXT, 'data', b'')

            ws.receive = receive

            with self.assertRaises(TypeError):
                yield from ws.receive_bytes()

        self.loop.run_until_complete(go())

    def test_send_str_nonstring(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        with self.assertRaises(TypeError):
            ws.send_str(b'bytes')

    def test_send_bytes_nonbytes(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        with self.assertRaises(TypeError):
            ws.send_bytes('string')

    def test_write(self):
        ws = WebSocketResponse()
        with self.assertRaises(RuntimeError):
            ws.write(b'data')

    def test_can_start_ok(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse(protocols=('chat',))
        self.assertEqual((True, 'chat'), ws.can_start(req))

    def test_can_start_unknown_protocol(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        self.assertEqual((True, None), ws.can_start(req))

    def test_can_start_invalid_method(self):
        req = self.make_request('POST', '/')
        ws = WebSocketResponse()
        self.assertEqual((False, None), ws.can_start(req))

    def test_can_start_without_upgrade(self):
        req = self.make_request('GET', '/',
                                headers=CIMultiDict({}))
        ws = WebSocketResponse()
        self.assertEqual((False, None), ws.can_start(req))

    def test_can_start_started(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        with self.assertRaisesRegex(RuntimeError, 'Already started'):
            ws.can_start(req)

    def test_closed_after_ctor(self):
        ws = WebSocketResponse()
        self.assertFalse(ws.closed)
        self.assertIsNone(ws.close_code)

    def test_send_str_closed(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        self.loop.run_until_complete(ws.close())
        with self.assertRaises(RuntimeError):
            ws.send_str('string')

    def test_send_bytes_closed(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        self.loop.run_until_complete(ws.close())
        with self.assertRaises(RuntimeError):
            ws.send_bytes(b'bytes')

    def test_ping_closed(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        self.loop.run_until_complete(ws.close())
        with self.assertRaises(RuntimeError):
            ws.ping()

    def test_pong_closed(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        self.loop.run_until_complete(ws.close())
        with self.assertRaises(RuntimeError):
            ws.pong()

    def test_close_idempotent(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        writer = mock.Mock()
        ws._writer = writer
        self.assertTrue(
            self.loop.run_until_complete(ws.close(code=1, message='message1')))
        self.assertTrue(ws.closed)
        self.assertFalse(
            self.loop.run_until_complete(ws.close(code=2, message='message2')))

    def test_start_invalid_method(self):
        req = self.make_request('POST', '/')
        ws = WebSocketResponse()
        with self.assertRaises(HTTPMethodNotAllowed):
            ws.start(req)

    def test_start_without_upgrade(self):
        req = self.make_request('GET', '/',
                                headers=CIMultiDict({}))
        ws = WebSocketResponse()
        with self.assertRaises(HTTPBadRequest):
            ws.start(req)

    def test_wait_closed_before_start(self):

        @asyncio.coroutine
        def go():
            ws = WebSocketResponse()
            with self.assertRaises(RuntimeError):
                yield from ws.close()

        self.loop.run_until_complete(go())

    def test_write_eof_not_started(self):

        @asyncio.coroutine
        def go():
            ws = WebSocketResponse()
            with self.assertRaises(RuntimeError):
                yield from ws.write_eof()

        self.loop.run_until_complete(go())

    def test_write_eof_idempotent(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        self.loop.run_until_complete(ws.close())

        @asyncio.coroutine
        def go():
            yield from ws.write_eof()
            yield from ws.write_eof()
            yield from ws.write_eof()

        self.loop.run_until_complete(go())

    def test_receive_exc_in_reader(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)

        exc = ValueError()
        res = asyncio.Future(loop=self.loop)
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
        ws.start(req)

        res = asyncio.Future(loop=self.loop)
        res.set_exception(asyncio.CancelledError())
        ws._reader.read.return_value = res

        self.assertRaises(
            asyncio.CancelledError,
            self.loop.run_until_complete, ws.receive())

    def test_receive_timeouterror(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)

        res = asyncio.Future(loop=self.loop)
        res.set_exception(asyncio.TimeoutError())
        ws._reader.read.return_value = res

        self.assertRaises(
            asyncio.TimeoutError,
            self.loop.run_until_complete, ws.receive())

    def test_receive_client_disconnected(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)

        exc = errors.ClientDisconnectedError()
        res = asyncio.Future(loop=self.loop)
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
        ws.start(req)
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
        ws.start(req)
        ws._waiting = True

        self.assertRaises(
            RuntimeError, self.loop.run_until_complete, ws.receive())

    def test_close_exc(self):
        req = self.make_request('GET', '/')
        reader = self.reader.set_parser.return_value = mock.Mock()

        ws = WebSocketResponse()
        ws.start(req)

        exc = ValueError()
        reader.read.return_value = asyncio.Future(loop=self.loop)
        reader.read.return_value.set_exception(exc)

        self.loop.run_until_complete(ws.close())
        self.assertTrue(ws.closed)
        self.assertIs(ws.exception(), exc)

        ws._closed = False
        reader.read.return_value = asyncio.Future(loop=self.loop)
        reader.read.return_value.set_exception(asyncio.CancelledError())
        self.assertRaises(asyncio.CancelledError,
                          self.loop.run_until_complete, ws.close())
        self.assertEqual(ws.close_code, 1006)

    def test_close_exc2(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)

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
