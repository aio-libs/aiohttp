import asyncio
import unittest
from unittest import mock
from aiohttp.multidict import CIMultiDict
from aiohttp.signals import Signal
from aiohttp.web import Application
from aiohttp.web import Request, StreamResponse, Response
from aiohttp.protocol import HttpVersion, HttpVersion11, HttpVersion10
from aiohttp.protocol import RawRequestMessage

class TestSignals(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path, headers=CIMultiDict(), app=None):
        message = RawRequestMessage(method, path, HttpVersion11, headers,
                                    False, False)
        return self.request_from_message(message, app)

    def request_from_message(self, message, app=None):
        self.app = app if app is not None else mock.Mock()
        self.payload = mock.Mock()
        self.transport = mock.Mock()
        self.reader = mock.Mock()
        self.writer = mock.Mock()
        req = Request(self.app, message, self.payload,
                      self.transport, self.reader, self.writer)
        return req

    def test_callback_valid(self):
        signal = Signal(parameters={'foo', 'bar'})

        # All these are suitable
        good_callbacks = map(asyncio.coroutine, [
            (lambda foo, bar: None),
            (lambda *, foo, bar: None),
            (lambda foo, bar, **kwargs: None),
            (lambda foo, bar, baz=None: None),
            (lambda baz=None, *, foo, bar: None),
            (lambda foo=None, bar=None: None),
            (lambda foo, bar=None, *, baz=None: None),
            (lambda **kwargs: None),
        ])
        for callback in good_callbacks:
            signal.append(callback)

    def test_callback_invalid(self):
        signal = Signal(parameters={'foo', 'bar'})

        # All these are unsuitable
        bad_callbacks = map(asyncio.coroutine, [
            (lambda foo: None),
            (lambda foo, bar, baz: None),
        ])
        for callback in bad_callbacks:
            with self.assertRaises(TypeError):
                signal.send(callback)

    def test_add_response_prepare_signal_handler(self):
        callback = asyncio.coroutine(lambda request, response: None)
        app = Application(loop=self.loop)
        app.on_response_prepare.append(callback)

    def test_add_signal_handler_not_a_callable(self):
        callback = True
        app = Application(loop=self.loop)
        with self.assertRaises(TypeError):
            app.on_response_prepare.append(callback)

    def test_function_signal_dispatch(self):
        signal = Signal(parameters={'foo', 'bar'})
        kwargs = {'foo': 1, 'bar': 2}

        callback_mock = mock.Mock()
        callback = asyncio.coroutine(callback_mock)

        signal.append(callback)

        self.loop.run_until_complete(signal.send(**kwargs))
        callback_mock.assert_called_once_with(**kwargs)

    def test_response_prepare(self):
        callback = mock.Mock()

        app = Application(loop=self.loop)
        app.on_response_prepare.append(asyncio.coroutine(callback))

        request = self.make_request('GET', '/', app=app)
        response = Response(body=b'')
        self.loop.run_until_complete(response.prepare(request))

        callback.assert_called_once_with(request=request,
                                         response=response)

