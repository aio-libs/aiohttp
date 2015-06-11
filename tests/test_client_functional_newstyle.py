"""Http client functional tests against aiohttp.web server"""

import asyncio
import socket
import unittest

import aiohttp
from aiohttp import client, web, log


class TestHttpClientFunctionalNewStyle(unittest.TestCase):

    def setUp(self):
        self.handler = None
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
    def create_server(self, method, path, handler=None):
        app = web.Application(loop=self.loop)
        if handler:
            app.router.add_route(method, path, handler)

        port = self.find_unused_port()
        self.handler = app.make_handler(
            debug=True, keep_alive_on=False,
            access_log=log.access_logger)
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    def test_keepalive_two_requests_sucess(self):
        @asyncio.coroutine
        def handler(request):
            body = yield from request.read()
            self.assertEqual(b'', body)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            connector = aiohttp.TCPConnector(loop=self.loop)
            r = yield from client.request('GET', url,
                                          connector=connector, loop=self.loop)
            yield from r.read()

            r2 = yield from client.request('GET', url,
                                           connector=connector, loop=self.loop)
            yield from r2.read()
            self.assertEqual(1, len(connector._conns))
            connector.close()

        self.loop.run_until_complete(go())

    def test_keepalive_response_released(self):
        @asyncio.coroutine
        def handler(request):
            body = yield from request.read()
            self.assertEqual(b'', body)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            connector = aiohttp.TCPConnector(loop=self.loop)
            r = yield from client.request('GET', url,
                                          connector=connector, loop=self.loop)
            yield from r.read()
            r.release()

            r2 = yield from client.request('GET', url,
                                           connector=connector, loop=self.loop)
            yield from r2.read()
            r2.release()
            self.assertEqual(1, len(connector._conns))
            connector.close()

        self.loop.run_until_complete(go())

    def test_keepalive_server_force_close_connection(self):
        @asyncio.coroutine
        def handler(request):
            body = yield from request.read()
            self.assertEqual(b'', body)
            response = web.Response(body=b'OK')
            response.force_close()
            return response

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)

            connector = aiohttp.TCPConnector(loop=self.loop)

            r = yield from client.request('GET', url,
                                          connector=connector, loop=self.loop)
            yield from r.read()
            self.assertEqual(0, len(connector._conns))

            r2 = yield from client.request('GET', url,
                                           connector=connector, loop=self.loop)
            yield from r2.read()

            self.assertEqual(0, len(connector._conns))
            connector.close()

        self.loop.run_until_complete(go())
