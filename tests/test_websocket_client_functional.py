import aiohttp
import asyncio
import socket
import unittest
from aiohttp import web


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
