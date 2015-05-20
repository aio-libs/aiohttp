import asyncio
import base64
import hashlib
import os
import socket
import unittest
from unittest import mock

import aiohttp
from aiohttp import errors, hdrs, web, websocket, websocket_client


class TestWebSocketClient(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.key_data = os.urandom(16)
        self.key = base64.b64encode(self.key_data)
        self.ws_key = base64.b64encode(
            hashlib.sha1(self.key + websocket.WS_KEY).digest()).decode()

    def tearDown(self):
        self.loop.close()

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
            hdrs.SEC_WEBSOCKET_PROTOCOL: 'chat'
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        res = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org',
                protocols=('t1', 't2', 'chat'),
                loop=self.loop))

        self.assertIsInstance(res, websocket_client.ClientWebSocketResponse)
        self.assertEqual(res.protocol, 'chat')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect_custom_response(self, m_req, m_os):

        class CustomResponse(websocket_client.ClientWebSocketResponse):
            def read(self, decode=False):
                return 'customized!'

        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        res = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org',
                ws_response_class=CustomResponse,
                loop=self.loop))

        self.assertEqual(res.read(), 'customized!')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect_global_loop(self, m_req, m_os):
        asyncio.set_event_loop(self.loop)

        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect('http://test.org'))
        self.assertIs(resp._loop, self.loop)

        asyncio.set_event_loop(None)

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect_err_status(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 500
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid response status')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect_err_upgrade(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: 'test',
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid upgrade header')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect_err_conn(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: 'close',
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid connection header')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_ws_connect_err_challenge(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: 'asdfasdfasdfasdfasdfasdf'
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid challenge response')

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_close(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)
        writer = WebSocketWriter.return_value = mock.Mock()
        reader = resp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect('http://test.org', loop=self.loop))
        self.assertFalse(resp.closed)

        msg = websocket.Message(websocket.MSG_CLOSE, b'', b'')
        reader.read.return_value = asyncio.Future(loop=self.loop)
        reader.read.return_value.set_result(msg)

        res = self.loop.run_until_complete(resp.close())
        writer.close.assert_called_with(1000, b'')
        self.assertTrue(resp.closed)
        self.assertTrue(res)
        self.assertIsNone(resp.exception())

        # idempotent
        res = self.loop.run_until_complete(resp.close())
        self.assertFalse(res)
        self.assertEqual(writer.close.call_count, 1)

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_close_exc(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()
        reader = resp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))
        self.assertFalse(resp.closed)

        exc = ValueError()
        reader.read.return_value = asyncio.Future(loop=self.loop)
        reader.read.return_value.set_exception(exc)

        self.loop.run_until_complete(resp.close())
        self.assertTrue(resp.closed)
        self.assertIs(resp.exception(), exc)

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_close_exc2(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)
        writer = WebSocketWriter.return_value = mock.Mock()
        resp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))
        self.assertFalse(resp.closed)

        exc = ValueError()
        writer.close.side_effect = exc

        self.loop.run_until_complete(resp.close())
        self.assertTrue(resp.closed)
        self.assertIs(resp.exception(), exc)

        resp._closed = False
        writer.close.side_effect = asyncio.CancelledError()
        self.assertRaises(asyncio.CancelledError,
                          self.loop.run_until_complete, resp.close())

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_send_data_after_close(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))
        resp._closed = True

        self.assertRaises(RuntimeError, resp.ping)
        self.assertRaises(RuntimeError, resp.pong)
        self.assertRaises(RuntimeError, resp.send_str, 's')
        self.assertRaises(RuntimeError, resp.send_bytes, b'b')

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_send_data_type_errors(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))

        self.assertRaises(TypeError, resp.send_str, b's')
        self.assertRaises(TypeError, resp.send_bytes, 'b')

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.request')
    def test_reader_read_exception(self, m_req, m_os, WebSocketWriter):
        hresp = mock.Mock()
        hresp.status = 101
        hresp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = asyncio.Future(loop=self.loop)
        m_req.return_value.set_result(hresp)
        WebSocketWriter.return_value = mock.Mock()
        reader = hresp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))

        exc = ValueError()
        reader.read.return_value = asyncio.Future(loop=self.loop)
        reader.read.return_value.set_exception(exc)

        msg = self.loop.run_until_complete(resp.receive())
        self.assertEqual(msg.tp, aiohttp.MsgType.error)
        self.assertIs(resp.exception(), exc)

    def test_receive_runtime_err(self):
        resp = websocket_client.ClientWebSocketResponse(
            mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), 10.0,
            True, True, self.loop)
        resp._waiting = True

        self.assertRaises(
            RuntimeError, self.loop.run_until_complete, resp.receive())


class TestWebSocketClientFunctional(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())

        self.loop.close()

    def find_unused_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @asyncio.coroutine
    def create_server(self, method, path, handler):
        app = web.Application(loop=self.loop)
        app.router.add_route(method, path, handler)

        port = self.find_unused_port()
        self.handler = app.make_handler()
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    def test_send_recv_text(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_str()
            ws.send_str(msg+'/answer')
            yield from ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_str('ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.data, 'ask/answer')
            yield from resp.close()

        self.loop.run_until_complete(go())

    def test_send_recv_bytes(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_bytes()
            ws.send_bytes(msg+b'/answer')
            yield from ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.data, b'ask/answer')

            yield from resp.close()

        self.loop.run_until_complete(go())

    def test_ping_pong(self):

        closed = asyncio.Future(loop=self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_bytes()
            ws.ping()
            ws.send_bytes(msg+b'/answer')
            try:
                yield from ws.close()
            finally:
                closed.set_result(1)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.ping()
            resp.send_bytes(b'ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.binary)
            self.assertEqual(msg.data, b'ask/answer')

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.close)

            yield from resp.close()
            yield from closed

        self.loop.run_until_complete(go())

    def test_ping_pong_manual(self):

        closed = asyncio.Future(loop=self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_bytes()
            ws.ping()
            ws.send_bytes(msg+b'/answer')
            try:
                yield from ws.close()
            finally:
                closed.set_result(1)
            return ws

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(
                url, autoping=False, loop=self.loop)
            resp.ping()
            resp.send_bytes(b'ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.pong)

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.ping)
            resp.pong()

            msg = yield from resp.receive()
            self.assertEqual(msg.data, b'ask/answer')

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.close)

            yield from closed

        self.loop.run_until_complete(go())

    def test_close(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            yield from ws.receive_bytes()
            ws.send_str('test')

            yield from ws.receive()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')

            closed = yield from resp.close()
            self.assertTrue(closed)
            self.assertTrue(resp.closed)
            self.assertEqual(resp.close_code, 1000)

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.closed)

        self.loop.run_until_complete(go())

    def test_close_from_server(self):

        closed = asyncio.Future(loop=self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            try:
                yield from ws.receive_bytes()
                yield from ws.close()
            finally:
                closed.set_result(1)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.close)
            self.assertTrue(resp.closed)

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.closed)

            yield from closed

        self.loop.run_until_complete(go())

    def test_close_manual(self):

        closed = asyncio.Future(loop=self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            yield from ws.receive_bytes()
            ws.send_str('test')

            try:
                yield from ws.close()
            finally:
                closed.set_result(1)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(
                url, autoclose=False, loop=self.loop)
            resp.send_bytes(b'ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.data, 'test')

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, aiohttp.MsgType.close)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, '')
            self.assertFalse(resp.closed)

            yield from resp.close()
            yield from closed
            self.assertTrue(resp.closed)

        self.loop.run_until_complete(go())

    def test_close_timeout(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)
            yield from ws.receive_bytes()
            ws.send_str('test')
            yield from asyncio.sleep(10, loop=self.loop)

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(
                url, timeout=0.2, autoclose=False, loop=self.loop)
            resp.send_bytes(b'ask')

            msg = yield from resp.receive()
            self.assertEqual(msg.data, 'test')
            self.assertEqual(msg.tp, aiohttp.MsgType.text)

            msg = yield from resp.close()
            self.assertTrue(resp.closed)
            self.assertIsInstance(resp.exception(), asyncio.TimeoutError)

        self.loop.run_until_complete(go())

    def test_close_cancel(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)
            yield from ws.receive_bytes()
            ws.send_str('test')
            yield from asyncio.sleep(10, loop=self.loop)

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(
                url, autoclose=False, loop=self.loop)
            resp.send_bytes(b'ask')

            text = yield from resp.receive()
            self.assertEqual(text.data, 'test')

            t = asyncio.async(resp.close(), loop=self.loop)
            yield from asyncio.sleep(0.1, loop=self.loop)
            t.cancel()
            yield from asyncio.sleep(0.1, loop=self.loop)
            self.assertTrue(resp.closed)
            self.assertIsNone(resp.exception())

        self.loop.run_until_complete(go())
