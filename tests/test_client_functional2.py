import asyncio
import io
import socket
import unittest
import ssl
import os.path

import aiohttp
from aiohttp import hdrs, log, web


class TestClientFunctional2(unittest.TestCase):

    def setUp(self):
        self.handler = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.client = aiohttp.ClientSession(loop=self.loop)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())
        self.client.close()
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()

    def find_unused_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @asyncio.coroutine
    def create_server(self, *, ssl_ctx=None):
        app = web.Application(loop=self.loop)

        port = self.find_unused_port()
        self.handler = app.make_handler(
            debug=True, keep_alive_on=False,
            access_log=log.access_logger)
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port, ssl=ssl_ctx)
        proto = 'https' if ssl_ctx else 'http'
        url = "{}://127.0.0.1:{}".format(proto, port)
        self.addCleanup(srv.close)
        return app, srv, url

    def test_auto_header_user_agent(self):
        @asyncio.coroutine
        def handler(request):
            self.assertIn('aiohttp', request.headers['user-agent'])
            return web.Response()

        @asyncio.coroutine
        def go():
            app, srv, url = yield from self.create_server()
            app.router.add_route('get', '/', handler)
            resp = yield from self.client.get(url+'/')
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_skip_auto_headers_user_agent(self):
        @asyncio.coroutine
        def handler(request):
            self.assertNotIn(hdrs.USER_AGENT, request.headers)
            return web.Response()

        @asyncio.coroutine
        def go():
            app, srv, url = yield from self.create_server()
            app.router.add_route('get', '/', handler)
            resp = yield from self.client.get(url+'/',
                                              skip_auto_headers=['user-agent'])
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_skip_default_auto_headers_user_agent(self):
        @asyncio.coroutine
        def handler(request):
            self.assertNotIn(hdrs.USER_AGENT, request.headers)
            return web.Response()

        @asyncio.coroutine
        def go():
            app, srv, url = yield from self.create_server()
            app.router.add_route('get', '/', handler)

            client = aiohttp.ClientSession(loop=self.loop,
                                           skip_auto_headers=['user-agent'])
            resp = yield from client.get(url+'/')
            self.assertEqual(200, resp.status)
            yield from resp.release()

            client.close()

        self.loop.run_until_complete(go())

    def test_skip_auto_headers_content_type(self):
        @asyncio.coroutine
        def handler(request):
            self.assertNotIn(hdrs.CONTENT_TYPE, request.headers)
            return web.Response()

        @asyncio.coroutine
        def go():
            app, srv, url = yield from self.create_server()
            app.router.add_route('get', '/', handler)
            resp = yield from self.client.get(
                url+'/',
                skip_auto_headers=['content-type'])
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_post_data_bytesio(self):
        data = b'some buffer'

        @asyncio.coroutine
        def handler(request):
            self.assertEqual(len(data), request.content_length)
            val = yield from request.read()
            self.assertEqual(data, val)
            return web.Response()

        @asyncio.coroutine
        def go():
            app, srv, url = yield from self.create_server()
            app.router.add_route('post', '/', handler)
            resp = yield from self.client.post(
                url+'/',
                data=io.BytesIO(data))
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_post_data_with_bytesio_file(self):
        data = b'some buffer'

        @asyncio.coroutine
        def handler(request):
            post_data = yield from request.post()
            self.assertEqual(['file'], list(post_data.keys()))
            self.assertEqual(data, post_data['file'].file.read())
            return web.Response()

        @asyncio.coroutine
        def go():
            app, srv, url = yield from self.create_server()
            app.router.add_route('post', '/', handler)
            resp = yield from self.client.post(
                url+'/',
                data={'file': io.BytesIO(data)})
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_client_ssl(self):
        here = os.path.dirname(__file__)
        connector = aiohttp.TCPConnector(verify_ssl=False, loop=self.loop)

        @asyncio.coroutine
        def handler(request):
            return web.HTTPOk(text='Test message')

        @asyncio.coroutine
        def go():
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_ctx.load_cert_chain(
                os.path.join(here, 'sample.crt'),
                os.path.join(here, 'sample.key'))

            app, _, url = yield from self.create_server(ssl_ctx=ssl_ctx)
            app.router.add_route('GET', '/', handler)

            r = yield from aiohttp.request(
                'GET', url,
                loop=self.loop, connector=connector)
            txt = yield from r.text()
            self.assertEqual(txt, 'Test message')

        self.loop.run_until_complete(go())
        connector.close()
