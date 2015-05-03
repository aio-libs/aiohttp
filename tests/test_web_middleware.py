import asyncio
import socket
import unittest
from aiohttp import web, request


class TestWebMiddlewareFunctional(unittest.TestCase):

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
    def create_server(self, method, path, handler, *middlewares):
        app = web.Application(loop=self.loop, middlewares=middlewares)
        app.router.add_route(method, path, handler)

        port = self.find_unused_port()
        self.handler = app.make_handler(debug=True)
        srv = yield from self.loop.create_server(self.handler, '127.0.0.1',
                                                 port)

        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    def test_middleware_modifies_response(self):

        @asyncio.coroutine
        def handler(request):
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def middleware_factory(app, handler):
            def middleware(request):
                resp = yield from handler(request)
                self.assertEqual(200, resp.status)
                resp.set_status(201)
                resp.text = resp.text + '[MIDDLEWARE]'
                return resp
            return middleware

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler,
                                                      middleware_factory)
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(201, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK[MIDDLEWARE]', txt)
        self.loop.run_until_complete(go())

    def test_middleware_handles_exception(self):

        @asyncio.coroutine
        def handler(request):
            raise RuntimeError('Error text')

        @asyncio.coroutine
        def middleware_factory(app, handler):
            def middleware(request):
                with self.assertRaises(RuntimeError) as ctx:
                    yield from handler(request)
                return web.Response(status=501,
                                    text=str(ctx.exception) + '[MIDDLEWARE]')

            return middleware

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler,
                                                      middleware_factory)
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(501, resp.status)
            txt = yield from resp.text()
            self.assertEqual('Error text[MIDDLEWARE]', txt)

        self.loop.run_until_complete(go())

    def test_middleware_chain(self):

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='OK')

        def make_factory(num):

            @asyncio.coroutine
            def factory(app, handler):

                def middleware(request):
                    resp = yield from handler(request)
                    resp.text = resp.text + '[{}]'.format(num)
                    return resp

                return middleware
            return factory

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler,
                                                      make_factory(1),
                                                      make_factory(2))
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK[2][1]', txt)

        self.loop.run_until_complete(go())
