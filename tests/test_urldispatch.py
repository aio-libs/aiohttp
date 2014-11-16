import asyncio
import os
import unittest
from unittest import mock
import aiohttp.web
from aiohttp.web import (UrlDispatcher, Request, Response,
                         HTTPMethodNotAllowed, HTTPNotFound, Entry)
from aiohttp.multidict import MultiDict
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
                                    MultiDict(), False, False)
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload,
                      self.transport, self.writer, 15)
        return req

    def test_add_route_root(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.endpoint)

    def test_add_route_simple(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/to/path', handler)
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.endpoint)

    def test_add_with_matchdict(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/{to}', handler)
        req = self.make_request('GET', '/handler/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 'tail'}, info)
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.endpoint)

    def test_add_with_endpoint(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/to/path', handler,
                              endpoint='endpoint')
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual('endpoint', info.endpoint)

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

    def test_double_add_url_with_the_same_endpoint(self):
        self.router.add_route('GET', '/get', lambda r: None, endpoint='name')

        regexp = ("Duplicate endpoint 'name', "
                  r"already handled by \[GET\] /get -> ")
        with self.assertRaisesRegex(ValueError, regexp):
            self.router.add_route('GET', '/get_other', lambda r: None,
                                  endpoint='name')

    def test_reverse_plain(self):
        self.router.add_route('GET', '/get', lambda r: None, endpoint='name')

        url = self.loop.run_until_complete(self.router.reverse('GET', 'name'))
        self.assertEqual('/get', url)

    def test_reverse_plain_with_parts(self):
        self.router.add_route('GET', '/get', lambda r: None, endpoint='name')

        with self.assertRaisesRegex(
                ValueError,
                "Plain endpoint doesn't allow parts parameter"):
            self.loop.run_until_complete(
                self.router.reverse('GET', 'name', parts={'a': 'b'}))

    def test_reverse_unknown_endpoint(self):
        with self.assertRaisesRegex(
                KeyError,
                r"\[GET\] 'unknown' endpoint not found"):
            self.loop.run_until_complete(self.router.reverse('GET', 'unknown'))

    def test_reverse_dynamic(self):
        self.router.add_route('GET', '/get/{name}',
                              lambda r: None, endpoint='name')

        url = self.loop.run_until_complete(
            self.router.reverse('GET', 'name', parts={'name': 'John'}))
        self.assertEqual('/get/John', url)

    def test_reverse_dynamic_without_parts(self):
        self.router.add_route('GET', '/get/{name}',
                              lambda r: None, endpoint='name')

        with self.assertRaisesRegex(
                ValueError,
                "Dynamic endpoint requires nonempty parts parameter"):
            self.loop.run_until_complete(self.router.reverse('GET', 'name'))

    def test_reverse_with_qs(self):
        self.router.add_route('GET', '/get', lambda r: None, endpoint='name')

        url = self.loop.run_until_complete(
            self.router.reverse('GET', 'name', query=[('a', 'b'), ('c', 1)]))

        self.assertEqual('/get?a=b&c=1', url)

    def test_reverse_nonstatic_with_filename(self):
        self.router.add_route('GET', '/get', lambda r: None, endpoint='name')

        with self.assertRaisesRegex(
                ValueError,
                "Cannot use filename with non-static route"):
            self.loop.run_until_complete(self.router.reverse('GET', 'name',
                                                             filename='a.txt'))

    def test_reverse_static(self):
        self.router.add_static('/st', os.path.dirname(aiohttp.__file__),
                               endpoint='static')

        url = self.loop.run_until_complete(
            self.router.reverse('GET', 'static', filename='/dir/a.txt'))

        self.assertEqual('/st/dir/a.txt', url)

    def test_reverse_static_without_filename(self):
        self.router.add_static('/st', os.path.dirname(aiohttp.__file__),
                               endpoint='static')

        with self.assertRaisesRegex(
                ValueError,
                'filename must be not empty for static routes'):
            self.loop.run_until_complete(self.router.reverse('GET', 'static'))

    def test_reverse_unknown_endpoint_type(self):
        self.router._register_endpoint(Entry('compiled', 'GET', 'handler',
                                             'endpoint', '/path', 'UNKNOWN'))

        with self.assertRaisesRegex(
                ValueError,
                'Not supported endpoint type UNKNOWN'):
            self.loop.run_until_complete(
                self.router.reverse('GET', 'endpoint'))
