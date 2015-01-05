import asyncio
import unittest
from unittest import mock
from aiohttp.multidict import MultiDict
from aiohttp.web import (Request, WebSocketResponse,
                         WebSocketDisconnectedError,
                         HTTPMethodNotAllowed, HTTPBadRequest)
from aiohttp.protocol import RawRequestMessage, HttpVersion11
from aiohttp import websocket


class TestWebWebSocket(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=None):
        self.app = mock.Mock()
        if headers is None:
            headers = MultiDict(
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
            ws.close()

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
            def receive_msg():
                return websocket.Message(websocket.MSG_BINARY, b'data', b'')

            ws.receive_msg = receive_msg

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
            def receive_msg():
                return websocket.Message(websocket.MSG_TEXT, 'data', b'')

            ws.receive_msg = receive_msg

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

    def test_nested_exception(self):

        @asyncio.coroutine
        def a():
            raise WebSocketDisconnectedError()

        @asyncio.coroutine
        def b():
            yield from a()

        @asyncio.coroutine
        def c():
            yield from b()

        with self.assertRaises(WebSocketDisconnectedError):
            self.loop.run_until_complete(c())

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
        req = self.make_request('GET', '/', headers=MultiDict())
        ws = WebSocketResponse()
        self.assertEqual((False, None), ws.can_start(req))

    def test_can_start_started(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        with self.assertRaisesRegex(RuntimeError, 'Already started'):
            ws.can_start(req)

    def test_closing_after_ctor(self):
        ws = WebSocketResponse()
        self.assertFalse(ws.closing)

    def test_send_str_closing(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        ws.close()
        with self.assertRaises(RuntimeError):
            ws.send_str('string')

    def test_send_bytes_closing(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        ws.close()
        with self.assertRaises(RuntimeError):
            ws.send_bytes(b'bytes')

    def test_ping_closing(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        ws.close()
        with self.assertRaises(RuntimeError):
            ws.ping()

    def test_pong_closing(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        ws.close()
        with self.assertRaises(RuntimeError):
            ws.pong()

    def test_double_close(self):
        req = self.make_request('GET', '/')
        ws = WebSocketResponse()
        ws.start(req)
        writer = mock.Mock()
        ws._writer = writer
        ws.close(code=1, message='message1')
        self.assertTrue(ws.closing)
        with self.assertRaisesRegex(RuntimeError, 'Already closing'):
            ws.close(code=2, message='message2')
        self.assertTrue(ws.closing)
        writer.close.assert_called_once_with(1, 'message1')

    def test_start_invalid_method(self):
        req = self.make_request('POST', '/')
        ws = WebSocketResponse()
        with self.assertRaises(HTTPMethodNotAllowed):
            ws.start(req)

    def test_start_without_upgrade(self):
        req = self.make_request('GET', '/', headers=MultiDict())
        ws = WebSocketResponse()
        with self.assertRaises(HTTPBadRequest):
            ws.start(req)

    def test_wait_closed_before_start(self):

        @asyncio.coroutine
        def go():
            ws = WebSocketResponse()
            with self.assertRaises(RuntimeError):
                yield from ws.wait_closed()

        self.loop.run_until_complete(go())
