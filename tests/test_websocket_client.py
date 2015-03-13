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

    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_ws_connect(self, m_client, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
            hdrs.SEC_WEBSOCKET_PROTOCOL: 'chat'
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)

        res = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org',
                protocols=('t1', 't2', 'chat'),
                loop=self.loop))

        self.assertIsInstance(res, websocket_client.ClientWebSocketResponse)
        self.assertEqual(res.protocol, 'chat')

    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_ws_connect_global_loop(self, m_client, m_os):
        asyncio.set_event_loop(self.loop)

        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect('http://test.org'))
        self.assertIs(resp._loop, self.loop)

        asyncio.set_event_loop(None)

    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_ws_connect_err_status(self, m_client, m_os):
        resp = mock.Mock()
        resp.status = 500
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid response status')

    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_ws_connect_err_upgrade(self, m_client, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: 'test',
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid upgrade header')

    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_ws_connect_err_conn(self, m_client, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: 'close',
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid connection header')

    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_ws_connect_err_challenge(self, m_client, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: 'asdfasdfasdfasdfasdfasdf'
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                websocket_client.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid challenge response')

    @mock.patch('aiohttp.websocket_client.WebSocketWriter')
    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_close(self, m_client, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)
        writer = WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))
        self.assertFalse(resp.closing)
        resp.close()
        writer.close.assert_called_with(1000, b'')
        self.assertTrue(resp.closing)

        # idempotent
        resp.close()
        self.assertEqual(writer.close.call_count, 1)

    @mock.patch('aiohttp.websocket_client.WebSocketWriter')
    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_send_data_after_close(self, m_client, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))
        resp.close()

        self.assertRaises(RuntimeError, resp.ping)
        self.assertRaises(RuntimeError, resp.send_str, 's')
        self.assertRaises(RuntimeError, resp.send_bytes, b'b')

    @mock.patch('aiohttp.websocket_client.WebSocketWriter')
    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_send_data_type_errors(self, m_client, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))

        self.assertRaises(TypeError, resp.send_str, b's')
        self.assertRaises(TypeError, resp.send_bytes, 'b')

    @mock.patch('aiohttp.websocket_client.WebSocketWriter')
    @mock.patch('aiohttp.websocket_client.os')
    @mock.patch('aiohttp.websocket_client.client')
    def test_reader_read_exception(self, m_client, m_os, WebSocketWriter):
        hresp = mock.Mock()
        hresp.status = 101
        hresp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_client.request.return_value = asyncio.Future(loop=self.loop)
        m_client.request.return_value.set_result(hresp)
        WebSocketWriter.return_value = mock.Mock()
        reader = hresp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            websocket_client.ws_connect(
                'http://test.org', loop=self.loop))

        exc = ValueError()
        reader.read.return_value = asyncio.Future(loop=self.loop)
        reader.read.return_value.set_exception(exc)

        with self.assertRaises(ValueError) as ctx:
            self.loop.run_until_complete(resp.receive())

        self.assertIs(ctx.exception, exc)

        with self.assertRaises(ValueError) as ctx:
            self.loop.run_until_complete(resp.wait_closed())

        self.assertIs(ctx.exception, exc)


class TestWebSocketClientFunctional(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
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
        srv = yield from self.loop.create_server(
            app.make_handler(), '127.0.0.1', port)
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
            ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_str('ask')

            msg = yield from resp.receive_str()
            self.assertEqual('ask/answer', msg)

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, websocket.MSG_CLOSE)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, b'')

            resp.close()
            yield from resp.wait_closed()

        self.loop.run_until_complete(go())

    def test_send_recv_bytes(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_bytes()
            ws.send_bytes(msg+b'/answer')
            ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')

            msg = yield from resp.receive_bytes()
            self.assertEqual(b'ask/answer', msg)

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, websocket.MSG_CLOSE)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, b'')

            resp.close()
            yield from resp.wait_closed()

        self.loop.run_until_complete(go())

    def test_send_recv_bytes_mismatch(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_bytes()
            ws.send_bytes(msg+b'/answer')
            ws.close()

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')

            try:
                yield from resp.receive_str()
            except TypeError:
                pass

            resp.close()

        self.loop.run_until_complete(go())

    def test_send_recv_str_mismatch(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_str()
            ws.send_str(msg+'/answer')
            ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_str('ask')

            try:
                yield from resp.receive_bytes()
            except TypeError:
                pass

            resp.close()

        self.loop.run_until_complete(go())

    def test_ping_pong(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            msg = yield from ws.receive_bytes()
            ws.ping()
            ws.send_bytes(msg+b'/answer')
            ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.ping()
            resp.send_bytes(b'ask')

            msg = yield from resp.receive_bytes()
            self.assertEqual(b'ask/answer', msg)

            msg = yield from resp.receive()
            self.assertEqual(msg.tp, websocket.MSG_CLOSE)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, b'')

            resp.close()
            yield from resp.wait_closed()

        self.loop.run_until_complete(go())

    def test_close(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            yield from ws.receive_bytes()
            ws.send_str('test')
            ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')

            yield from resp.receive_str()
            msg = yield from resp.receive()
            self.assertEqual(msg.tp, websocket.MSG_CLOSE)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, b'')

        self.loop.run_until_complete(go())

    def test_close_from_server(self):

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.start(request)

            yield from ws.receive_bytes()
            ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'ask')
            resp.close()

            try:
                yield from resp.receive_bytes()
            except errors.WSServerDisconnectedError:
                pass
            else:
                self.fail()

        self.loop.run_until_complete(go())
