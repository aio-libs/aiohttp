import asyncio
import gc
from typing import Any
from unittest import mock

import pytest

from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ConnectionKey
from aiohttp.connector import BaseConnector, Connection


@pytest.fixture
def key() -> object:
    return object()


@pytest.fixture
def loop() -> Any:
    return mock.create_autospec(asyncio.AbstractEventLoop, spec_set=True, instance=True)


@pytest.fixture
def connector() -> mock.Mock:
    return mock.Mock()


@pytest.fixture
def protocol() -> mock.Mock:
    return mock.Mock(should_close=False)


def test_ctor(connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop) -> None:
    conn = Connection(connector, key, protocol, loop)
    assert conn.protocol is protocol
    conn.close()


def test_callbacks_on_close(connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop) -> None:
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb() -> None:
        nonlocal notified
        notified = True

    conn.add_callback(cb)
    conn.close()
    assert notified


def test_callbacks_on_release(
    connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop
) -> None:
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb() -> None:
        nonlocal notified
        notified = True

    conn.add_callback(cb)
    conn.release()
    assert notified


def test_callbacks_exception(
    connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop
) -> None:
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb1() -> None:
        raise Exception

    def cb2() -> None:
        nonlocal notified
        notified = True

    conn.add_callback(cb1)
    conn.add_callback(cb2)
    conn.close()
    assert notified


def test_del(connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: mock.Mock) -> None:
    loop.is_closed.return_value = False
    conn = Connection(connector, key, protocol, loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    connector._release.assert_called_with(key, protocol, should_close=True)  # type: ignore[attr-defined]
    msg = {
        "client_connection": mock.ANY,  # conn was deleted
        "message": "Unclosed connection",
    }
    msg["source_traceback"] = mock.ANY
    loop.call_exception_handler.assert_called_with(msg)


def test_close(connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop) -> None:
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.close()
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=True)  # type: ignore[attr-defined]
    assert conn.closed


def test_release(connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop) -> None:
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.release()
    assert protocol.transport is not None
    assert not protocol.transport.close.called  # type: ignore[attr-defined]
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=False)  # type: ignore[attr-defined]
    assert conn.closed


def test_release_proto_should_close(
    connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop
) -> None:
    protocol.should_close = True  # type: ignore[misc]
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.release()
    assert protocol.transport is not None
    assert not protocol.transport.close.called  # type: ignore[attr-defined]
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=True)  # type: ignore[attr-defined]
    assert conn.closed


def test_release_released(connector: BaseConnector, key: ConnectionKey, protocol: ResponseHandler, loop: asyncio.AbstractEventLoop) -> None:
    conn = Connection(connector, key, protocol, loop)
    conn.release()
    connector._release.reset_mock()  # type: ignore[attr-defined]
    conn.release()
    assert protocol.transport is not None
    assert not protocol.transport.close.called  # type: ignore[attr-defined]
    assert conn._protocol is None
    assert not connector._release.called  # type: ignore[attr-defined]
