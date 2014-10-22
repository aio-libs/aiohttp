import asyncio
import json
import socket
import unittest
from aiohttp import web, request


class TestWebFunctional(unittest.TestCase):

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
        srv = yield from self.loop.create_server(app.make_handler,
                                                 '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    def test_simple_get(self):

        @asyncio.coroutine
        def handler(request):
            body = yield from request.read()
            self.assertEqual(b'', body)
            return web.Response(request, b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK', txt)

        self.loop.run_until_complete(go())

    def test_post_form(self):

        @asyncio.coroutine
        def handler(request):
            data = yield from request.POST()
            self.assertEqual({'a': '1', 'b': '2'}, dict(data))
            return web.Response(request, b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data={'a': 1, 'b': 2},
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK', txt)

        self.loop.run_until_complete(go())

    def test_post_text(self):

        @asyncio.coroutine
        def handler(request):
            data = yield from request.text()
            self.assertEqual('русский', data)
            return web.Response(request, data.encode('utf8'))

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data='русский',
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('русский', txt)

        self.loop.run_until_complete(go())

    def test_post_json(self):

        dct = {'key': 'текст'}

        @asyncio.coroutine
        def handler(request):
            data = yield from request.json()
            self.assertEqual(dct, data)
            resp = web.Response(request)
            resp.content_type = 'application/json'
            resp.body = json.dumps(data).encode('utf8')
            return resp

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            headers = {'Content-Type': 'application/json'}
            resp = yield from request('POST', url, data=json.dumps(dct),
                                      headers=headers,
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            data = yield from resp.json()
            self.assertEqual(dct, data)

        self.loop.run_until_complete(go())

    def test_render_redirect(self):

        @asyncio.coroutine
        def handler(request):
            raise web.HTTPMovedPermanently(request, location='/path')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop,
                                      allow_redirects=False)
            self.assertEqual(301, resp.status)
            txt = yield from resp.text()
            self.assertEqual('', txt)
            self.assertEqual('/path', resp.headers['location'])

        self.loop.run_until_complete(go())
