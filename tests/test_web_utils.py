import asyncio
import socket
import unittest
from unittest import mock

import aiohttp
from aiohttp import web
from aiohttp.web_utils import normalize_path_middleware


class TestWebFunctional(unittest.TestCase):

    def setUp(self):
        self.handler = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.client = aiohttp.ClientSession(loop=self.loop)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())
        self.client.close()
        self.loop.close()

    def find_unused_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @asyncio.coroutine
    def create_server(self, method, path, handler, middleware):
        app = web.Application(loop=self.loop, middlewares=[middleware])

        app.router.add_route(method, path, handler)

        port = self.find_unused_port()
        self.handler = app.make_handler(
            debug=True, keep_alive_on=False)

        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port)
        base_url = "http://127.0.0.1:{}".format(port)
        self.addCleanup(srv.close)
        return base_url

    def test_not_found_trivial(self):
        mware = normalize_path_middleware(merge_slashes=False,
                                          append_slash=False)

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/path',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path/')
            self.assertEqual(404, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_append_slash(self):
        mware = normalize_path_middleware(merge_slashes=False,
                                          append_slash=True)

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/path/',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path')
            self.assertEqual(200, resp.status)
            body = yield from resp.text()
            self.assertEqual('ok', body)

        self.loop.run_until_complete(go())

    def test_append_slash_with_qs(self):
        mware = normalize_path_middleware(merge_slashes=False,
                                          append_slash=True)

        @asyncio.coroutine
        def handler(request):
            self.assertEqual(request.query_string, 'a=b')
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/path/',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path?a=b')
            self.assertEqual(200, resp.status)
            body = yield from resp.text()
            self.assertEqual('ok', body)

        self.loop.run_until_complete(go())

    def test_append_slash_not_found(self):
        mware = normalize_path_middleware(merge_slashes=False,
                                          append_slash=True)

        handler = mock.Mock()

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/other_path',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path')
            self.assertEqual(404, resp.status)
            resp.close()
            self.assertFalse(handler.called)

        self.loop.run_until_complete(go())

    def test_append_slash_not_found_because_already_ended_with_slash(self):
        mware = normalize_path_middleware(merge_slashes=False,
                                          append_slash=True)

        handler = mock.Mock()

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/other_path',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path/')
            self.assertEqual(404, resp.status)
            resp.close()
            self.assertFalse(handler.called)

        self.loop.run_until_complete(go())

    def test_merge_slashes(self):
        mware = normalize_path_middleware(merge_slashes=True,
                                          append_slash=False)

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/path/to',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path//to')
            self.assertEqual(200, resp.status)
            body = yield from resp.text()
            self.assertEqual('ok', body)

        self.loop.run_until_complete(go())

    def test_merge_multiple_slashes(self):
        mware = normalize_path_middleware(merge_slashes=True,
                                          append_slash=False)

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/path/to/entity',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path//to///entity')
            self.assertEqual(200, resp.status)
            body = yield from resp.text()
            self.assertEqual('ok', body)

        self.loop.run_until_complete(go())

    def test_merge_slashes_not_found(self):
        mware = normalize_path_middleware(merge_slashes=True,
                                          append_slash=False)

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/other',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path//to')
            self.assertEqual(404, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_merge_slashes_has_no_doubles(self):
        mware = normalize_path_middleware(merge_slashes=True,
                                          append_slash=False)

        @asyncio.coroutine
        def handler(request):
            return web.Response(text='ok')

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/other',
                                                     handler,
                                                     mware)
            resp = yield from self.client.get(base_url + '/path/to')
            self.assertEqual(404, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_skip_if_has_body(self):
        mware = normalize_path_middleware(merge_slashes=True,
                                          append_slash=True)

        handler = mock.Mock()

        @asyncio.coroutine
        def go():
            base_url = yield from self.create_server('GET',
                                                     '/other_path',
                                                     handler,
                                                     mware)
            resp = yield from self.client.post(base_url + '/path/',
                                               data={'a': 'b'})
            self.assertEqual(404, resp.status)
            resp.close()
            self.assertFalse(handler.called)

        self.loop.run_until_complete(go())
