import gc
from unittest import mock

import pytest

from aiohttp.connector import Connection


@pytest.fixture
def key():
    return object()


@pytest.fixture
def connector():
    return mock.Mock()


@pytest.fixture
def request():
    return mock.Mock()


@pytest.fixture
def transport():
    return mock.Mock()


@pytest.fixture
def protocol():
    return mock.Mock()


def test_del(connector, key, request, transport, protocol, loop):
    conn = Connection(connector, key, request,
                      transport, protocol, loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    connector._release.assert_called_with(key,
                                          request,
                                          transport,
                                          protocol,
                                          should_close=True)
    msg = {'client_connection': mock.ANY,  # conn was deleted
           'message': 'Unclosed connection'}
    if loop.get_debug():
        msg['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(loop, msg)


def test_close(connector, key, request, transport, protocol, loop):
    conn = Connection(connector, key, request,
                      transport, protocol, loop)
    assert not conn.closed
    conn.close()
    assert conn._transport is None
    connector._release.assert_called_with(
        key, request, transport, protocol,
        should_close=True)
    assert conn.closed


def test_release(connector, key, request, transport, protocol, loop):
    conn = Connection(connector, key, request,
                      transport, protocol, loop)
    assert not conn.closed
    conn.release()
    assert not transport.close.called
    assert conn._transport is None
    connector._release.assert_called_with(
        key, request, transport, protocol,
        should_close=False)
    assert conn.closed


def test_release_released(connector, key, request, transport, protocol, loop):
    conn = Connection(connector, key, request,
                      transport, protocol, loop)
    conn.release()
    connector._release.reset_mock()
    conn.release()
    assert not transport.close.called
    assert conn._transport is None
    assert not connector._release.called


def test_detach(connector, key, request, transport, protocol, loop):
    conn = Connection(connector, key, request,
                      transport, protocol, loop)
    assert not conn.closed
    conn.detach()
    assert conn._transport is None
    assert not connector._release.called
    assert conn.closed
