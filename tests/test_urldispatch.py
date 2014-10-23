import asyncio
import unittest
from unittest import mock
from aiohttp.web import (UrlDispatcher, Request, Response,
                         HTTPMethodNotAllowed, HTTPNotFound)
from aiohttp.multidict import MultiDict
from aiohttp.protocol import HttpVersion, RawRequestMessage


class TestUrlDispatcher(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.router = UrlDispatcher()

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=MultiDict(), *,
                     version=HttpVersion(1, 1), closing=False):
        self.app = mock.Mock()
        message = RawRequestMessage(method, path, version, headers, closing,
                                    False)
        self.payload = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload, self.writer)
        return req

    def test_add_route_root(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)

    def test_add_route_simple(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/to/path', handler)
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)

    def test_add_with_matchdict(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/{to}', handler)
        req = self.make_request('GET', '/handler/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 'tail'}, info)
        self.assertIs(handler, info.handler)

    def test_add_with_tailing_slash(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/to/path/', handler)
        req = self.make_request('GET', '/handler/to/path/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info)
        self.assertIs(handler, info.handler)

    def test_add_invalid_path(self):
        with self.assertRaises(ValueError):
            self.router.add_route('GET', '/{/', lambda req: None)

    def test_add_url_invalid1(self):
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id', lambda: None)

    def test_add_url_invalid2(self):
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id{}}', lambda: None)

    def test_add_url_invalid3(self):
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id{}', lambda: None)

    def test_add_url_invalid4(self):
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id"}', lambda: None)

    def test_add_url_invalid5(self):
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post"{id}', lambda: None)

    def test_add_url_escaping(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/+$', handler)

        req = self.make_request('GET', '/+$')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertIs(handler, info.handler)

    def test_match_second_result_in_table(self):
        handler1 = lambda req: Response(req)
        handler2 = lambda req: Response(req)
        self.router.add_route('GET', '/h1', handler1)
        self.router.add_route('POST', '/h2', handler2)
        req = self.make_request('POST', '/h2')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info)
        self.assertIs(handler2, info.handler)

    def test_raise_method_not_allowed(self):
        handler1 = lambda req: Response(req)
        handler2 = lambda req: Response(req)
        self.router.add_route('GET', '/', handler1)
        self.router.add_route('POST', '/', handler2)
        req = self.make_request('PUT', '/')

        with self.assertRaises(HTTPMethodNotAllowed) as ctx:
            self.loop.run_until_complete(self.router.resolve(req))

        exc = ctx.exception
        self.assertEqual('PUT', exc.method)
        self.assertEqual(405, exc.status)
        self.assertEqual({'POST', 'GET'}, exc.allowed_methods)

    def test_raise_method_not_found(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/a', handler)
        req = self.make_request('GET', '/b')

        with self.assertRaises(HTTPNotFound) as ctx:
            self.loop.run_until_complete(self.router.resolve(req))

        exc = ctx.exception
        self.assertEqual(404, exc.status)
