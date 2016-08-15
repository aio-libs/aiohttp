import asyncio
import base64
import hashlib
import os
import unittest

import aiohttp
from aiohttp import WSMsgType, helpers, web
from aiohttp._ws_impl import WebSocketParser, WebSocketWriter
from aiohttp.test_utils import unused_port

WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class TestWebWebSocketFunctional(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    @asyncio.coroutine
    def create_server(self, method, path, handler):
        app = web.Application(loop=self.loop)
        app.router.add_route(method, path, handler)

        port = unused_port()
        srv = yield from self.loop.create_server(
            app.make_handler(), '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    @asyncio.coroutine
    def connect_ws(self, url, protocol=None):
        sec_key = base64.b64encode(os.urandom(16))

        conn = aiohttp.TCPConnector(loop=self.loop)
        self.addCleanup(conn.close)

        headers = {
            'UPGRADE': 'WebSocket',
            'CONNECTION': 'Upgrade',
            'SEC-WEBSOCKET-VERSION': '13',
            'SEC-WEBSOCKET-KEY': sec_key.decode(),
        }

        if protocol:
            headers['SEC-WEBSOCKET-PROTOCOL'] = protocol

        # send request
        response = yield from aiohttp.request(
            'get', url,
            headers=headers,
            connector=conn,
            loop=self.loop)
        self.addCleanup(response.close)

        self.assertEqual(101, response.status)
        self.assertEqual(response.headers.get('upgrade', '').lower(),
                         'websocket')
        self.assertEqual(response.headers.get('connection', '').lower(),
                         'upgrade')

        key = response.headers.get('sec-websocket-accept', '').encode()
        match = base64.b64encode(hashlib.sha1(sec_key + WS_KEY).digest())
        self.assertEqual(key, match)

        # switch to websocket protocol
        connection = response.connection
        reader = connection.reader.set_parser(WebSocketParser)
        writer = WebSocketWriter(connection.writer)

        return response, reader, writer

    def test_auto_pong_with_closing_by_peer(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            yield from ws.prepare(request)
            yield from ws.receive()

            msg = yield from ws.receive()
            self.assertEqual(msg.type, WSMsgType.CLOSE)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, 'exit message')
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, reader, writer = yield from self.connect_ws(url)
            writer.ping()
            writer.send('ask')

            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.PONG)
            writer.close(1000, 'exit message')
            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_ping(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            yield from ws.prepare(request)

            ws.ping('data')
            yield from ws.receive()
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, reader, writer = yield from self.connect_ws(url)
            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.PING)
            self.assertEqual(msg.data, b'data')
            writer.pong()
            writer.close(2, 'exit message')
            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_client_ping(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            yield from ws.prepare(request)

            yield from ws.receive()
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, reader, writer = yield from self.connect_ws(url)
            writer.ping('data')
            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.PONG)
            self.assertEqual(msg.data, b'data')
            writer.pong()
            writer.close()
            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_pong(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse(autoping=False)
            yield from ws.prepare(request)

            msg = yield from ws.receive()
            self.assertEqual(msg.type, WSMsgType.PING)
            ws.pong('data')

            msg = yield from ws.receive()
            self.assertEqual(msg.type, WSMsgType.CLOSE)
            self.assertEqual(msg.data, 1000)
            self.assertEqual(msg.extra, 'exit message')
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, reader, writer = yield from self.connect_ws(url)
            writer.ping('data')
            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.PONG)
            self.assertEqual(msg.data, b'data')
            writer.close(1000, 'exit message')

            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_change_status(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            ws.set_status(200)
            self.assertEqual(200, ws.status)
            yield from ws.prepare(request)
            self.assertEqual(101, ws.status)
            yield from ws.close()
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, _, writer = yield from self.connect_ws(url)
            writer.close()
            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_handle_protocol(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse(protocols=('foo', 'bar'))
            yield from ws.prepare(request)
            yield from ws.close()
            self.assertEqual('bar', ws.protocol)
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, _, writer = yield from self.connect_ws(url, 'eggs, bar')
            writer.close()

            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_server_close_handshake(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse(protocols=('foo', 'bar'))
            yield from ws.prepare(request)
            yield from ws.close()
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, reader, writer = yield from self.connect_ws(url, 'eggs, bar')

            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.CLOSE)
            writer.close()
            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_client_close_handshake(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse(
                autoclose=False, protocols=('foo', 'bar'))
            yield from ws.prepare(request)

            msg = yield from ws.receive()
            self.assertEqual(msg.type, WSMsgType.CLOSE)
            self.assertFalse(ws.closed)
            yield from ws.close()
            self.assertTrue(ws.closed)
            self.assertEqual(ws.close_code, 1007)

            msg = yield from ws.receive()
            self.assertEqual(msg.type, WSMsgType.CLOSED)

            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp, reader, writer = yield from self.connect_ws(url, 'eggs, bar')

            writer.close(code=1007)
            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.CLOSE)
            yield from closed
            resp.close()

        self.loop.run_until_complete(go())

    def test_server_close_handshake_server_eats_client_messages(self):

        closed = helpers.create_future(self.loop)

        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse(protocols=('foo', 'bar'))
            yield from ws.prepare(request)
            yield from ws.close()
            closed.set_result(None)
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            response, reader, writer = yield from self.connect_ws(
                url, 'eggs, bar')

            msg = yield from reader.read()
            self.assertEqual(msg.type, WSMsgType.CLOSE)

            writer.send('text')
            writer.send(b'bytes', binary=True)
            writer.ping()

            writer.close()
            yield from closed

            response.close()

        self.loop.run_until_complete(go())

    def test_receive_msg(self):
        @asyncio.coroutine
        def handler(request):
            ws = web.WebSocketResponse()
            yield from ws.prepare(request)

            with self.assertWarns(DeprecationWarning):
                msg = yield from ws.receive_msg()
                self.assertEqual(msg.data, b'data')
            yield from ws.close()
            return ws

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from aiohttp.ws_connect(url, loop=self.loop)
            resp.send_bytes(b'data')
            yield from resp.close()

        self.loop.run_until_complete(go())
