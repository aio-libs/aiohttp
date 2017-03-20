import asyncio
from unittest import mock

import pytest
from multidict import CIMultiDict

from aiohttp.signals import Signal
from aiohttp.test_utils import make_mocked_request
from aiohttp.web import Application, Response


@pytest.fixture
def app():
    return Application()


@pytest.fixture
def debug_app():
    return Application(debug=True)


def make_request(app, method, path, headers=CIMultiDict()):
    return make_mocked_request(method, path, headers, app=app)


@asyncio.coroutine
def test_add_signal_handler_not_a_callable(app):
    callback = True
    app.on_response_prepare.append(callback)
    with pytest.raises(TypeError):
        yield from app.on_response_prepare(None, None)


@asyncio.coroutine
def test_function_signal_dispatch(app):
    signal = Signal(app)
    kwargs = {'foo': 1, 'bar': 2}

    callback_mock = mock.Mock()

    @asyncio.coroutine
    def callback(**kwargs):
        callback_mock(**kwargs)

    signal.append(callback)

    yield from signal.send(**kwargs)
    callback_mock.assert_called_once_with(**kwargs)


@asyncio.coroutine
def test_function_signal_dispatch2(app):
    signal = Signal(app)
    args = {'a', 'b'}
    kwargs = {'foo': 1, 'bar': 2}

    callback_mock = mock.Mock()

    @asyncio.coroutine
    def callback(*args, **kwargs):
        callback_mock(*args, **kwargs)

    signal.append(callback)

    yield from signal.send(*args, **kwargs)
    callback_mock.assert_called_once_with(*args, **kwargs)


@asyncio.coroutine
def test_response_prepare(app):
    callback = mock.Mock()

    @asyncio.coroutine
    def cb(*args, **kwargs):
        callback(*args, **kwargs)

    app.on_response_prepare.append(cb)

    request = make_request(app, 'GET', '/')
    response = Response(body=b'')
    yield from response.prepare(request)

    callback.assert_called_once_with(request, response)


@asyncio.coroutine
def test_non_coroutine(app):
    signal = Signal(app)
    kwargs = {'foo': 1, 'bar': 2}

    callback = mock.Mock()

    signal.append(callback)

    yield from signal.send(**kwargs)
    callback.assert_called_once_with(**kwargs)


@asyncio.coroutine
def test_debug_signal(debug_app):
    assert debug_app.debug, "Should be True"
    signal = Signal(debug_app)

    callback = mock.Mock()
    pre = mock.Mock()
    post = mock.Mock()

    signal.append(callback)
    debug_app.on_pre_signal.append(pre)
    debug_app.on_post_signal.append(post)

    yield from signal.send(1, a=2)
    callback.assert_called_once_with(1, a=2)
    pre.assert_called_once_with(1, 'aiohttp.signals:Signal', 1, a=2)
    post.assert_called_once_with(1, 'aiohttp.signals:Signal', 1, a=2)


def test_setitem(app):
    signal = Signal(app)
    m1 = mock.Mock()
    signal.append(m1)
    assert signal[0] is m1
    m2 = mock.Mock()
    signal[0] = m2
    assert signal[0] is m2


def test_delitem(app):
    signal = Signal(app)
    m1 = mock.Mock()
    signal.append(m1)
    assert len(signal) == 1
    del signal[0]
    assert len(signal) == 0


def test_cannot_append_to_frozen_signal(app):
    signal = Signal(app)
    m1 = mock.Mock()
    m2 = mock.Mock()
    signal.append(m1)
    signal.freeze()
    with pytest.raises(RuntimeError):
        signal.append(m2)

    assert list(signal) == [m1]


def test_cannot_setitem_in_frozen_signal(app):
    signal = Signal(app)
    m1 = mock.Mock()
    m2 = mock.Mock()
    signal.append(m1)
    signal.freeze()
    with pytest.raises(RuntimeError):
        signal[0] = m2

    assert list(signal) == [m1]


def test_cannot_delitem_in_frozen_signal(app):
    signal = Signal(app)
    m1 = mock.Mock()
    signal.append(m1)
    signal.freeze()
    with pytest.raises(RuntimeError):
        del signal[0]

    assert list(signal) == [m1]
