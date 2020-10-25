from unittest import mock

import pytest
from multidict import CIMultiDict
from re_assert import Matches

from aiohttp.signals import Signal
from aiohttp.test_utils import make_mocked_coro, make_mocked_request
from aiohttp.web import Application, Response


@pytest.fixture
def app():
    return Application()


def make_request(app, method, path, headers=CIMultiDict()):
    return make_mocked_request(method, path, headers, app=app)


async def test_add_signal_handler_not_a_callable(app) -> None:
    callback = True
    app.on_response_prepare.append(callback)
    app.on_response_prepare.freeze()
    with pytest.raises(TypeError):
        await app.on_response_prepare(None, None)


async def test_function_signal_dispatch(app) -> None:
    signal = Signal(app)
    kwargs = {"foo": 1, "bar": 2}

    callback_mock = mock.Mock()

    async def callback(**kwargs):
        callback_mock(**kwargs)

    signal.append(callback)
    signal.freeze()

    await signal.send(**kwargs)
    callback_mock.assert_called_once_with(**kwargs)


async def test_function_signal_dispatch2(app) -> None:
    signal = Signal(app)
    args = {"a", "b"}
    kwargs = {"foo": 1, "bar": 2}

    callback_mock = mock.Mock()

    async def callback(*args, **kwargs):
        callback_mock(*args, **kwargs)

    signal.append(callback)
    signal.freeze()

    await signal.send(*args, **kwargs)
    callback_mock.assert_called_once_with(*args, **kwargs)


async def test_response_prepare(app) -> None:
    callback = mock.Mock()

    async def cb(*args, **kwargs):
        callback(*args, **kwargs)

    app.on_response_prepare.append(cb)
    app.on_response_prepare.freeze()

    request = make_request(app, "GET", "/")
    response = Response(body=b"")
    await response.prepare(request)

    callback.assert_called_once_with(request, response)


async def test_non_coroutine(app) -> None:
    signal = Signal(app)
    kwargs = {"foo": 1, "bar": 2}

    callback = mock.Mock()

    signal.append(callback)
    signal.freeze()

    with pytest.raises(TypeError):
        await signal.send(**kwargs)


def test_setitem(app) -> None:
    signal = Signal(app)
    m1 = mock.Mock()
    signal.append(m1)
    assert signal[0] is m1
    m2 = mock.Mock()
    signal[0] = m2
    assert signal[0] is m2


def test_delitem(app) -> None:
    signal = Signal(app)
    m1 = mock.Mock()
    signal.append(m1)
    assert len(signal) == 1
    del signal[0]
    assert len(signal) == 0


def test_cannot_append_to_frozen_signal(app) -> None:
    signal = Signal(app)
    m1 = mock.Mock()
    m2 = mock.Mock()
    signal.append(m1)
    signal.freeze()
    with pytest.raises(RuntimeError):
        signal.append(m2)

    assert list(signal) == [m1]


def test_cannot_setitem_in_frozen_signal(app) -> None:
    signal = Signal(app)
    m1 = mock.Mock()
    m2 = mock.Mock()
    signal.append(m1)
    signal.freeze()
    with pytest.raises(RuntimeError):
        signal[0] = m2

    assert list(signal) == [m1]


def test_cannot_delitem_in_frozen_signal(app) -> None:
    signal = Signal(app)
    m1 = mock.Mock()
    signal.append(m1)
    signal.freeze()
    with pytest.raises(RuntimeError):
        del signal[0]

    assert list(signal) == [m1]


async def test_cannot_send_non_frozen_signal(app) -> None:
    signal = Signal(app)

    callback = make_mocked_coro()

    signal.append(callback)

    with pytest.raises(RuntimeError):
        await signal.send()

    assert not callback.called


async def test_repr(app) -> None:
    signal = Signal(app)

    callback = make_mocked_coro()

    signal.append(callback)

    assert Matches(
        r"<Signal owner=<Application .+>, frozen=False, " r"\[<Mock id='\d+'>\]>"
    ) == repr(signal)
