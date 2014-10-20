import asyncio
import unittest
from unittest import mock
from aiohttp.web import UrlDispatcher, Request, Response
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
        self.assertEqual({}, info.match_dict)
        self.assertIs(handler, info.handler)

    def test_add_route_simple(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/to/path', handler)
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info.match_dict)
        self.assertIs(handler, info.handler)

    def test_add_with_matchdict(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/{to}', handler)
        req = self.make_request('GET', '/handler/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 'tail'}, info.match_dict)
        self.assertIs(handler, info.handler)

    def test_add_with_tailing_slash(self):
        handler = lambda req: Response(req)
        self.router.add_route('GET', '/handler/to/path/', handler)
        req = self.make_request('GET', '/handler/to/path/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info.match_dict)
        self.assertIs(handler, info.handler)

    def test_add_invalid_path(self):
        with self.assertRaises(ValueError):
            self.router.add_route('GET', '/{/', lambda req: None)
