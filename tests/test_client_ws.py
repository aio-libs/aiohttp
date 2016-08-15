import asyncio
import base64
import hashlib
import os
import unittest
from unittest import mock

import aiohttp
from aiohttp import ClientWebSocketResponse, errors, hdrs, helpers
from aiohttp._ws_impl import WS_KEY


class TestWebSocketClient(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.key_data = os.urandom(16)
        self.key = base64.b64encode(self.key_data)
        self.ws_key = base64.b64encode(
            hashlib.sha1(self.key + WS_KEY).digest()).decode()

    def tearDown(self):
        self.loop.close()

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
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
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        res = self.loop.run_until_complete(
            aiohttp.ws_connect(
                'http://test.org',
                protocols=('t1', 't2', 'chat'),
                loop=self.loop))

        self.assertIsInstance(res, ClientWebSocketResponse)
        self.assertEqual(res.protocol, 'chat')
        self.assertNotIn(hdrs.ORIGIN, m_req.call_args[1]["headers"])

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_with_origin(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 403
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        origin = 'https://example.org/page.html'
        with self.assertRaises(errors.WSServerHandshakeError):
            self.loop.run_until_complete(
                aiohttp.ws_connect(
                    'http://test.org',
                    loop=self.loop,
                    origin=origin))

        self.assertIn(hdrs.ORIGIN, m_req.call_args[1]["headers"])
        self.assertEqual(m_req.call_args[1]["headers"][hdrs.ORIGIN], origin)

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_custom_response(self, m_req, m_os):

        class CustomResponse(ClientWebSocketResponse):
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
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        res = self.loop.run_until_complete(
            aiohttp.ws_connect(
                'http://test.org',
                ws_response_class=CustomResponse,
                loop=self.loop))

        self.assertEqual(res.read(), 'customized!')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
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
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect('http://test.org'))
        self.assertIs(resp._loop, self.loop)

        asyncio.set_event_loop(None)

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_err_status(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 500
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                aiohttp.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid response status')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_err_upgrade(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: 'test',
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                aiohttp.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid upgrade header')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_err_conn(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: 'close',
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                aiohttp.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid connection header')

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_err_challenge(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: 'asdfasdfasdfasdfasdfasdf'
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError) as ctx:
            self.loop.run_until_complete(
                aiohttp.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        self.assertEqual(
            ctx.exception.message, 'Invalid challenge response')

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_close(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)
        writer = WebSocketWriter.return_value = mock.Mock()
        reader = resp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect('http://test.org', loop=self.loop))
        self.assertFalse(resp.closed)

        msg = aiohttp.WSMessage(aiohttp.MsgType.CLOSE, b'', b'')
        reader.read.return_value = helpers.create_future(self.loop)
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
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_close_exc(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()
        reader = resp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect(
                'http://test.org', loop=self.loop))
        self.assertFalse(resp.closed)

        exc = ValueError()
        reader.read.return_value = helpers.create_future(self.loop)
        reader.read.return_value.set_exception(exc)

        self.loop.run_until_complete(resp.close())
        self.assertTrue(resp.closed)
        self.assertIs(resp.exception(), exc)

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_close_exc2(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)
        writer = WebSocketWriter.return_value = mock.Mock()
        resp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect(
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
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_send_data_after_close(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect(
                'http://test.org', loop=self.loop))
        resp._closed = True

        self.assertRaises(RuntimeError, resp.ping)
        self.assertRaises(RuntimeError, resp.pong)
        self.assertRaises(RuntimeError, resp.send_str, 's')
        self.assertRaises(RuntimeError, resp.send_bytes, b'b')
        self.assertRaises(RuntimeError, resp.send_json, {})

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_send_data_type_errors(self, m_req, m_os, WebSocketWriter):
        resp = mock.Mock()
        resp.status = 101
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)
        WebSocketWriter.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect(
                'http://test.org', loop=self.loop))

        self.assertRaises(TypeError, resp.send_str, b's')
        self.assertRaises(TypeError, resp.send_bytes, 'b')
        self.assertRaises(TypeError, resp.send_json, set())

    @mock.patch('aiohttp.client.WebSocketWriter')
    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_reader_read_exception(self, m_req, m_os, WebSocketWriter):
        hresp = mock.Mock()
        hresp.status = 101
        hresp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key,
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(hresp)
        WebSocketWriter.return_value = mock.Mock()
        reader = hresp.connection.reader.set_parser.return_value = mock.Mock()

        resp = self.loop.run_until_complete(
            aiohttp.ws_connect(
                'http://test.org', loop=self.loop))

        exc = ValueError()
        reader.read.return_value = helpers.create_future(self.loop)
        reader.read.return_value.set_exception(exc)

        msg = self.loop.run_until_complete(resp.receive())
        self.assertEqual(msg.type, aiohttp.MsgType.ERROR)
        self.assertIs(msg.type, msg.tp)
        self.assertIs(resp.exception(), exc)

    def test_receive_runtime_err(self):
        resp = ClientWebSocketResponse(
            mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock(), 10.0,
            True, True, self.loop)
        resp._waiting = True

        self.assertRaises(
            RuntimeError, self.loop.run_until_complete, resp.receive())

    @mock.patch('aiohttp.client.os')
    @mock.patch('aiohttp.client.ClientSession.get')
    def test_ws_connect_close_resp_on_err(self, m_req, m_os):
        resp = mock.Mock()
        resp.status = 500
        resp.headers = {
            hdrs.UPGRADE: hdrs.WEBSOCKET,
            hdrs.CONNECTION: hdrs.UPGRADE,
            hdrs.SEC_WEBSOCKET_ACCEPT: self.ws_key
        }
        m_os.urandom.return_value = self.key_data
        m_req.return_value = helpers.create_future(self.loop)
        m_req.return_value.set_result(resp)

        with self.assertRaises(errors.WSServerHandshakeError):
            self.loop.run_until_complete(
                aiohttp.ws_connect(
                    'http://test.org',
                    protocols=('t1', 't2', 'chat'),
                    loop=self.loop))
        resp.close.assert_called_with()
