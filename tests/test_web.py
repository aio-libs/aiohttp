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

    def test_app_register_on_finish(self):
        app = web.Application(loop=self.loop)
        cb1 = mock.Mock()
        cb2 = mock.Mock()
        app.register_on_finish(cb1, 1, b=2)
        app.register_on_finish(cb2, 2, c=3)
        self.loop.run_until_complete(app.finish())
        cb1.assert_called_once_with(app, 1, b=2)
        cb2.assert_called_once_with(app, 2, c=3)

    def test_app_register_coro(self):
        app = web.Application(loop=self.loop)

        fut = asyncio.Future(loop=self.loop)

        @asyncio.coroutine
        def cb(app):
            yield from asyncio.sleep(0.001, loop=self.loop)
            fut.set_result(123)

        app.register_on_finish(cb)
        self.loop.run_until_complete(app.finish())
        self.assertTrue(fut.done())
        self.assertEqual(123, fut.result())

    def test_app_error_in_finish_callbacks(self):
        app = web.Application(loop=self.loop)

        err = RuntimeError('bad call')
        app.register_on_finish(mock.Mock(side_effect=err))
        handler = mock.Mock()
        self.loop.set_exception_handler(handler)
        self.loop.run_until_complete(app.finish())
        exc_info = {'exception': err,
                    'application': app,
                    'message': 'Error in finish callback'}
        handler.assert_called_once_with(self.loop, exc_info)

    def test_non_default_router(self):
        router = web.UrlDispatcher()
        app = web.Application(loop=self.loop, router=router)
        self.assertIs(router, app.router)

    def test_connections(self):
        app = web.Application(loop=self.loop)
        self.assertEqual(app.connections, [])

        handler = object()
        transport = object()
        app.connection_made(handler, transport)
        self.assertEqual(app.connections, [handler])

        app.connection_lost(handler, None)
        self.assertEqual(app.connections, [])

    def test_finish_connection_no_timeout(self):
        app = web.Application(loop=self.loop)
        handler = mock.Mock()
        transport = mock.Mock()
        app.connection_made(handler, transport)

        self.loop.run_until_complete(app.finish_connections())

        app.connection_lost(handler, None)
        self.assertEqual(app.connections, [])
        handler.closing.assert_called_with()
        transport.close.assert_called_with()

    def test_finish_connection_timeout(self):
        app = web.Application(loop=self.loop)
        handler = mock.Mock()
        transport = mock.Mock()
        app.connection_made(handler, transport)

        self.loop.run_until_complete(app.finish_connections(timeout=0.1))

        app.connection_lost(handler, None)
        self.assertEqual(app.connections, [])
        handler.closing.assert_called_with()
        transport.close.assert_called_with()
