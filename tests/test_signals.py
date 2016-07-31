import asyncio
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp.protocol import HttpVersion11, RawRequestMessage
from aiohttp.signals import Signal
from aiohttp.web import Application, Request, Response


@pytest.fixture
def app(loop):
    return Application(loop=loop)


@pytest.fixture
def debug_app(loop):
    return Application(loop=loop, debug=True)


def make_request(app, method, path, headers=CIMultiDict()):
    message = RawRequestMessage(method, path, HttpVersion11, headers,
                                [(k.encode('utf-8'), v.encode('utf-8'))
                                 for k, v in headers.items()],
                                False, False)
    return request_from_message(message, app)


def request_from_message(message, app):
    payload = mock.Mock()
    transport = mock.Mock()
    reader = mock.Mock()
    writer = mock.Mock()
    req = Request(app, message, payload,
                  transport, reader, writer)
    return req


def test_add_response_prepare_signal_handler(loop, app):
    callback = asyncio.coroutine(lambda request, response: None)
    app.on_response_prepare.append(callback)


def test_add_signal_handler_not_a_callable(loop, app):
    callback = True
    app.on_response_prepare.append(callback)
    with pytest.raises(TypeError):
        app.on_response_prepare(None, None)


def test_function_signal_dispatch(loop, app):
    signal = Signal(app)
    kwargs = {'foo': 1, 'bar': 2}

    callback_mock = mock.Mock()

    @asyncio.coroutine
    def callback(**kwargs):
        callback_mock(**kwargs)

    signal.append(callback)

    loop.run_until_complete(signal.send(**kwargs))
    callback_mock.assert_called_once_with(**kwargs)


def test_function_signal_dispatch2(loop, app):
    signal = Signal(app)
    args = {'a', 'b'}
    kwargs = {'foo': 1, 'bar': 2}

    callback_mock = mock.Mock()

    @asyncio.coroutine
    def callback(*args, **kwargs):
        callback_mock(*args, **kwargs)

    signal.append(callback)

    loop.run_until_complete(signal.send(*args, **kwargs))
    callback_mock.assert_called_once_with(*args, **kwargs)


def test_response_prepare(loop, app):
    callback = mock.Mock()

    @asyncio.coroutine
    def cb(*args, **kwargs):
        callback(*args, **kwargs)

    app.on_response_prepare.append(cb)

    request = make_request(app, 'GET', '/')
    response = Response(body=b'')
    loop.run_until_complete(response.prepare(request))

    callback.assert_called_once_with(request,
                                     response)


def test_non_coroutine(loop, app):
    signal = Signal(app)
    kwargs = {'foo': 1, 'bar': 2}

    callback = mock.Mock()

    signal.append(callback)

    loop.run_until_complete(signal.send(**kwargs))
    callback.assert_called_once_with(**kwargs)


def test_copy_forbidden(app):
    signal = Signal(app)
    with pytest.raises(NotImplementedError):
        signal.copy()


def test_sort_forbidden(app):
    def l1():
        pass

    def l2():
        pass

    def l3():
        pass

    signal = Signal(app)
    signal.extend([l1, l2, l3])
    with pytest.raises(NotImplementedError):
        signal.sort()
    assert signal == [l1, l2, l3]


def test_debug_signal(loop, debug_app):
    assert debug_app.debug, "Should be True"
    signal = Signal(debug_app)

    callback = mock.Mock()
    pre = mock.Mock()
    post = mock.Mock()

    signal.append(callback)
    debug_app.on_pre_signal.append(pre)
    debug_app.on_post_signal.append(post)

    loop.run_until_complete(signal.send(1, a=2))
    callback.assert_called_once_with(1, a=2)
    pre.assert_called_once_with(1, 'aiohttp.signals:Signal', 1, a=2)
    post.assert_called_once_with(1, 'aiohttp.signals:Signal', 1, a=2)
