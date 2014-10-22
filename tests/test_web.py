import asyncio
import unittest
from unittest import mock

from aiohttp import web
from aiohttp.multidict import MultiDict
from aiohttp.protocol import HttpVersion11, RawRequestMessage


class TestWeb(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_handler_returns_not_response(self):
        app = web.Application(loop=self.loop)

        def handler(request):
            return 'abc'

        app.router.add_route('GET', '/', handler)
        h = app.make_handler()
        message = RawRequestMessage('GET', '/', HttpVersion11,
                                    MultiDict(), False, False)
        payload = mock.Mock()

        with self.assertRaises(RuntimeError):
            self.loop.run_until_complete(h.handle_request(message, payload))

    def test_app_loop(self):
        app = web.Application(loop=self.loop)
        self.assertIs(self.loop, app.loop)

    def test_app_default_loop(self):
        asyncio.set_event_loop(self.loop)
        app = web.Application()
        self.assertIs(self.loop, app.loop)
