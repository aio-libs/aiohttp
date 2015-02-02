import asyncio
import os
import unittest
from unittest import mock
import aiohttp.web
from aiohttp.web import (UrlDispatcher, Request, Response,
                         HTTPMethodNotAllowed, HTTPNotFound)
from aiohttp.multidict import CIMultiDict
from aiohttp.protocol import HttpVersion, RawRequestMessage


class TestUrlDispatcher(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.router = UrlDispatcher()

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path):
        self.app = mock.Mock()
        message = RawRequestMessage(method, path, HttpVersion(1, 1),
                                    CIMultiDict(), False, False)
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.reader = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload,
                      self.transport, self.reader, self.writer)
        return req

    def make_handler(self):

        @asyncio.coroutine
        def handler(request):
            return Response(request)  # pragma: no cover

        return handler

    def test_add_route_root(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_simple(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/to/path', handler)
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_with_matchdict(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/{to}', handler)
        req = self.make_request('GET', '/handler/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 'tail'}, info)
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_with_name(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/to/path', handler,
                              name='name')
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual('name', info.route.name)

    def test_add_with_tailing_slash(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/to/path/', handler)
        req = self.make_request('GET', '/handler/to/path/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info)
        self.assertIs(handler, info.handler)

    def test_add_invalid_path(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('GET', '/{/', handler)

    def test_add_url_invalid1(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id', handler)

    def test_add_url_invalid2(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id{}}', handler)

    def test_add_url_invalid3(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id{}', handler)

    def test_add_url_invalid4(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id"}', handler)

    def test_add_url_invalid5(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post"{id}', handler)

    def test_add_url_escaping(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/+$', handler)

        req = self.make_request('GET', '/+$')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertIs(handler, info.handler)

    def test_match_second_result_in_table(self):
        handler1 = self.make_handler()
        handler2 = self.make_handler()
        self.router.add_route('GET', '/h1', handler1)
        self.router.add_route('POST', '/h2', handler2)
        req = self.make_request('POST', '/h2')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info)
        self.assertIs(handler2, info.handler)

    def test_raise_method_not_allowed(self):
        handler1 = self.make_handler()
        handler2 = self.make_handler()
        self.router.add_route('GET', '/', handler1)
        self.router.add_route('POST', '/', handler2)
        req = self.make_request('PUT', '/')

        match_info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNone(match_info.route)
        self.assertEqual({}, match_info)

        with self.assertRaises(HTTPMethodNotAllowed) as ctx:
            self.loop.run_until_complete(match_info.handler(req))

        exc = ctx.exception
        self.assertEqual('PUT', exc.method)
        self.assertEqual(405, exc.status)
        self.assertEqual({'POST', 'GET'}, exc.allowed_methods)

    def test_raise_method_not_found(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/a', handler)
        req = self.make_request('GET', '/b')

        match_info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNone(match_info.route)
        self.assertEqual({}, match_info)

        with self.assertRaises(HTTPNotFound) as ctx:
            self.loop.run_until_complete(match_info.handler(req))

        exc = ctx.exception
        self.assertEqual(404, exc.status)

    def test_double_add_url_with_the_same_name(self):
        handler1 = self.make_handler()
        handler2 = self.make_handler()
        self.router.add_route('GET', '/get', handler1, name='name')

        regexp = ("Duplicate 'name', already handled by")
        with self.assertRaisesRegex(ValueError, regexp):
            self.router.add_route('GET', '/get_other', handler2, name='name')

    def test_route_plain(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get', handler, name='name')
        route2 = self.router['name']
        url = route2.url()
        self.assertEqual('/get', url)
        self.assertIs(route, route2)

    def test_route_unknown_route_name(self):
        with self.assertRaises(KeyError):
            self.router['unknown']

    def test_route_dynamic(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get/{name}', handler,
                                      name='name')

        route2 = self.router['name']
        url = route2.url(parts={'name': 'John'})
        self.assertEqual('/get/John', url)
        self.assertIs(route, route2)

    def test_route_with_qs(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get', handler, name='name')

        url = self.router['name'].url(query=[('a', 'b'), ('c', 1)])
        self.assertEqual('/get?a=b&c=1', url)

    def test_add_static(self):
        route = self.router.add_static('/st',
                                       os.path.dirname(aiohttp.__file__),
                                       name='static')
        route2 = self.router['static']
        url = route2.url(filename='/dir/a.txt')
        self.assertEqual('/st/dir/a.txt', url)
        self.assertIs(route, route2)

    def test_plain_not_match(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/path', handler, name='name')
        route = self.router['name']
        self.assertIsNone(route.match('/another/path'))

    def test_dynamic_not_match(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/{name}', handler, name='name')
        route = self.router['name']
        self.assertIsNone(route.match('/another/path'))

    def test_static_not_match(self):
        self.router.add_static('/pre', os.path.dirname(aiohttp.__file__),
                               name='name')
        route = self.router['name']
        self.assertIsNone(route.match('/another/path'))

    def test_dynamic_with_trailing_slash(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/{name}/', handler, name='name')
        route = self.router['name']
        self.assertEqual({'name': 'John'}, route.match('/get/John/'))

    def test_len(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get1', handler, name='name1')
        self.router.add_route('GET', '/get2', handler, name='name2')
        self.assertEqual(2, len(self.router))

    def test_iter(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get1', handler, name='name1')
        self.router.add_route('GET', '/get2', handler, name='name2')
        self.assertEqual({'name1', 'name2'}, set(iter(self.router)))

    def test_contains(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get1', handler, name='name1')
        self.router.add_route('GET', '/get2', handler, name='name2')
        self.assertIn('name1', self.router)
        self.assertNotIn('name3', self.router)

    def test_plain_repr(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/path', handler, name='name')
        self.assertRegex(repr(self.router['name']),
                         r"<PlainRoute 'name' \[GET\] /get/path")

    def test_dynamic_repr(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/{path}', handler, name='name')
        self.assertRegex(repr(self.router['name']),
                         r"<DynamicRoute 'name' \[GET\] /get/{path}")

    def test_static_repr(self):
        self.router.add_static('/get', os.path.dirname(aiohttp.__file__),
                               name='name')
        self.assertRegex(repr(self.router['name']),
                         r"<StaticRoute 'name' \[GET\] /get/")

    def test_static_adds_slash(self):
        route = self.router.add_static('/prefix',
                                       os.path.dirname(aiohttp.__file__))
        self.assertEqual('/prefix/', route._prefix)

    def test_static_dont_add_trailing_slash(self):
        route = self.router.add_static('/prefix/',
                                       os.path.dirname(aiohttp.__file__))
        self.assertEqual('/prefix/', route._prefix)

    def test_add_route_with_re(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:\d+}', handler)

        req = self.make_request('GET', '/handler/1234')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': '1234'}, info)

    def test_add_route_with_re_not_match(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:\d+}', handler)

        req = self.make_request('GET', '/handler/tail')
        match_info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNone(match_info.route)
        self.assertEqual({}, match_info)
        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(match_info.handler(req))

    def test_add_route_with_re_including_slashes(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:.+}/tail', handler)

        req = self.make_request('GET', '/handler/re/with/slashes/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 're/with/slashes'}, info)

    def test_add_route_with_invalid_re(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError) as ctx:
            self.router.add_route('GET', r'/handler/{to:+++}', handler)
        self.assertEqual(
            "Bad pattern '/handler/(?P<to>+++)': nothing to repeat",
            str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)

    def test_route_dynamic_with_regex_spec(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get/{num:^\d+}', handler,
                                      name='name')

        url = route.url(parts={'num': '123'})
        self.assertEqual('/get/123', url)

    def test_route_dynamic_with_regex_spec_and_trailing_slash(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get/{num:^\d+}/', handler,
                                      name='name')

        url = route.url(parts={'num': '123'})
        self.assertEqual('/get/123/', url)

    def test_regular_match_info(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/get/{name}', handler)

            req = self.make_request('GET', '/get/john')
            match_info = yield from self.router.resolve(req)
            self.maxDiff = None
            self.assertRegex(repr(match_info),
                             "<MatchInfo {'name': 'john'}: <DynamicRoute.+>>")

        self.loop.run_until_complete(go())

    def test_not_found_repr(self):

        @asyncio.coroutine
        def go():
            req = self.make_request('POST', '/path/to')
            match_info = yield from self.router.resolve(req)
            self.assertEqual("<MatchInfo: not found>", repr(match_info))

        self.loop.run_until_complete(go())

    def test_not_allowed_repr(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/path/to', handler)

            handler2 = self.make_handler()
            self.router.add_route('POST', '/path/to', handler2)

            req = self.make_request('PUT', '/path/to')
            match_info = yield from self.router.resolve(req)
            self.assertEqual("<MatchInfo: method PUT is not allowed "
                             "(allowed methods: GET, POST>", repr(match_info))

        self.loop.run_until_complete(go())
