import gc
from unittest import mock

import pytest

from aiohttp.connector import Connection


@pytest.fixture
def key():
    return object()


@pytest.fixture
def request():
    return mock.Mock()


@pytest.fixture
def loop():
    return mock.Mock()


@pytest.fixture
def connector():
    return mock.Mock()


@pytest.fixture
def protocol():
    return mock.Mock(should_close=False)


def test_ctor(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    assert conn.loop is loop
    assert conn.protocol is protocol
    assert conn.writer is protocol.writer
    conn.close()


def test_callbacks_on_close(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb():
        nonlocal notified
        notified = True

    conn.add_callback(cb)
    conn.close()
    assert notified


def test_callbacks_on_release(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb():
        nonlocal notified
        notified = True

    conn.add_callback(cb)
    conn.release()
    assert notified


def test_callbacks_on_detach(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb():
        nonlocal notified
        notified = True

    conn.add_callback(cb)
    conn.detach()
    assert notified


def test_callbacks_exception(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    notified = False

    def cb1():
        raise Exception

    def cb2():
        nonlocal notified
        notified = True

    conn.add_callback(cb1)
    conn.add_callback(cb2)
    conn.close()
    assert notified


def test_del(connector, key, protocol, loop):
    loop.is_closed.return_value = False
    conn = Connection(connector, key, protocol, loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    connector._release.assert_called_with(key, protocol, should_close=True)
    msg = {'client_connection': mock.ANY,  # conn was deleted
           'message': 'Unclosed connection'}
    if loop.get_debug():
        msg['source_traceback'] = mock.ANY
    loop.call_exception_handler.assert_called_with(msg)


def test_close(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.close()
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=True)
    assert conn.closed


def test_release(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.release()
    assert not protocol.transport.close.called
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=False)
    assert conn.closed


def test_release_proto_should_close(connector, key, protocol, loop):
    protocol.should_close = True
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.release()
    assert not protocol.transport.close.called
    assert conn._protocol is None
    connector._release.assert_called_with(key, protocol, should_close=True)
    assert conn.closed


def test_release_released(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    conn.release()
    connector._release.reset_mock()
    conn.release()
    assert not protocol.transport.close.called
    assert conn._protocol is None
    assert not connector._release.called


def test_detach(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    assert not conn.closed
    conn.detach()
    assert conn._protocol is None
    assert connector._release_acquired.called
    assert not connector._release.called
    assert conn.closed


def test_detach_closed(connector, key, protocol, loop):
    conn = Connection(connector, key, protocol, loop)
    conn.release()
    conn.detach()

    assert not connector._release_acquired.called
    assert conn._protocol is None
