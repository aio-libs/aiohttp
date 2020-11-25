import gc
from typing import Any
from unittest import mock

import pytest

from aiohttp.connector import Connection


@pytest.fixture
def key() -> object:
    return object()


@pytest.fixture
def loop() -> Any:
    return mock.Mock()


@pytest.fixture
def connector() -> Any:
    return mock.Mock()


@pytest.fixture
def protocol() -> Any:
    return mock.Mock(should_close=False)


def test_ctor(connector: Any, key: Any, protocol: Any, loop: Any) -> None:
    conn = Connection(connector, key, protocol, loop)
    assert conn.protocol is protocol
    conn.close()


def test_callbacks_on_close(connector: Any, key: Any, protocol: Any, loop: Any) -> None:
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb() -> None:
        nonlocal notified
        notified = True

    conn.add_callback(cb)
    conn.close()
    assert notified


def test_callbacks_on_release(
    connector: Any, key: Any, protocol: Any, loop: Any
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
    connector: Any, key: Any, protocol: Any, loop: Any
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


def test_del(connector: Any, key: Any, protocol: Any, loop: Any) -> None:
    loop.is_closed.return_value = False
    conn = Connection(connector, key, protocol, loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    connector._release.assert_called_with(key, protocol, should_close=True)
    msg = {
        "client_connection": mock.ANY,  # conn was deleted
        "message": "Unclosed connection",
    }
    if loop.get_debug():
        msg["source_traceback"] = mock.ANY
    loop.call_exception_handler.assert_called_with(msg)


def test_close(connector: Any, key: Any, protocol: Any, loop: Any) -> None:
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.close()
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=True)
    assert conn.closed


def test_release(connector: Any, key: Any, protocol: Any, loop: Any) -> None:
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.release()
    assert not protocol.transport.close.called
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=False)
    assert conn.closed


def test_release_proto_should_close(
    connector: Any, key: Any, protocol: Any, loop: Any
) -> None:
    protocol.should_close = True
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.release()
    assert not protocol.transport.close.called
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=True)
    assert conn.closed


def test_release_released(connector: Any, key: Any, protocol: Any, loop: Any) -> None:
    conn = Connection(connector, key, protocol, loop)
    conn.release()
    connector._release.reset_mock()
    conn.release()
    assert not protocol.transport.close.called
    assert conn._protocol is None
    assert not connector._release.called
