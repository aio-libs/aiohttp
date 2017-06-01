"""Tests of http client with custom Connector"""

import asyncio
import gc
import os.path
import platform
import shutil
import socket
import ssl
import tempfile
import unittest
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import client, helpers, web
from aiohttp.client import ClientRequest
from aiohttp.connector import Connection, _DNSCacheTable
from aiohttp.test_utils import unused_port


@pytest.fixture()
def key():
    """Connection key"""
    return ('localhost1', 80, False)


@pytest.fixture
def key2():
    """Connection key"""
    return ('localhost2', 80, False)


@pytest.fixture
def ssl_key():
    """Connection key"""
    return ('localhost', 80, True)


def test_del(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    proto = mock.Mock(should_close=False)
    conn._release('a', proto)
    conns_impl = conn._conns

    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    assert not conns_impl
    proto.close.assert_called_with()
    msg = {'connector': mock.ANY,  # conn was deleted
           'connections': mock.ANY,
           'message': 'Unclosed connector'}
    if loop.get_debug():
        msg['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(loop, msg)


@pytest.mark.xfail
@asyncio.coroutine
def test_del_with_scheduled_cleanup(loop):
    loop.set_debug(True)
    conn = aiohttp.BaseConnector(loop=loop, keepalive_timeout=0.01)
    transp = mock.Mock()
    conn._conns['a'] = [(transp, 'proto', 123)]

    conns_impl = conn._conns
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        # obviously doesn't deletion because loop has a strong
        # reference to connector's instance method, isn't it?
        del conn
        yield from asyncio.sleep(0.01, loop=loop)
        gc.collect()

    assert not conns_impl
    transp.close.assert_called_with()
    msg = {'connector': mock.ANY,  # conn was deleted
           'message': 'Unclosed connector'}
    if loop.get_debug():
        msg['source_traceback'] = mock.ANY
    exc_handler.assert_called_with(loop, msg)


def test_del_with_closed_loop(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    transp = mock.Mock()
    conn._conns['a'] = [(transp, 'proto', 123)]

    conns_impl = conn._conns
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)
    loop.close()

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    assert not conns_impl
    assert not transp.close.called
    assert exc_handler.called


def test_del_empty_conector(loop):
    conn = aiohttp.BaseConnector(loop=loop)

    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    del conn

    assert not exc_handler.called


@asyncio.coroutine
def test_create_conn(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    with pytest.raises(NotImplementedError):
        yield from conn._create_connection(object())


def test_context_manager(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    conn.close = mock.Mock()

    with conn as c:
        assert conn is c

    assert conn.close.called


def test_ctor_loop():
    with mock.patch('aiohttp.connector.asyncio') as m_asyncio:
        session = aiohttp.BaseConnector()

    assert session._loop is m_asyncio.get_event_loop.return_value


def test_close(loop):
    proto = mock.Mock()

    conn = aiohttp.BaseConnector(loop=loop)
    assert not conn.closed
    conn._conns[('host', 8080, False)] = [(proto, object())]
    conn.close()

    assert not conn._conns
    assert proto.close.called
    assert conn.closed


def test_get(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    assert conn._get(1) is None

    proto = mock.Mock()
    conn._conns[1] = [(proto, loop.time())]
    assert conn._get(1) == proto
    conn.close()


def test_get_expired(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    assert conn._get(('localhost', 80, False)) is None

    proto = mock.Mock()
    conn._conns[('localhost', 80, False)] = [(proto, loop.time() - 1000)]
    assert conn._get(('localhost', 80, False)) is None
    assert not conn._conns
    conn.close()


def test_get_expired_ssl(loop):
    conn = aiohttp.BaseConnector(loop=loop, enable_cleanup_closed=True)
    assert conn._get(('localhost', 80, True)) is None

    proto = mock.Mock()
    conn._conns[('localhost', 80, True)] = [(proto, loop.time() - 1000)]
    assert conn._get(('localhost', 80, True)) is None
    assert not conn._conns
    assert conn._cleanup_closed_transports == [proto.close.return_value]
    conn.close()


def test_release_acquired(loop, key):
    proto = mock.Mock()
    conn = aiohttp.BaseConnector(loop=loop, limit=5)
    conn._release_waiter = mock.Mock()

    conn._acquired.add(proto)
    conn._acquired_per_host[key].add(proto)
    conn._release_acquired(key, proto)
    assert 0 == len(conn._acquired)
    assert 0 == len(conn._acquired_per_host)
    assert conn._release_waiter.called

    conn._release_acquired(key, proto)
    assert 0 == len(conn._acquired)
    assert 0 == len(conn._acquired_per_host)

    conn.close()


def test_release_acquired_closed(loop, key):
    proto = mock.Mock()
    conn = aiohttp.BaseConnector(loop=loop, limit=5)
    conn._release_waiter = mock.Mock()

    conn._acquired.add(proto)
    conn._acquired_per_host[key].add(proto)
    conn._closed = True
    conn._release_acquired(key, proto)
    assert 1 == len(conn._acquired)
    assert 1 == len(conn._acquired_per_host[key])
    assert not conn._release_waiter.called
    conn.close()


def test_release(loop, key):
    conn = aiohttp.BaseConnector(loop=loop)
    conn._release_waiter = mock.Mock()

    proto = mock.Mock(should_close=False)

    conn._acquired.add(proto)
    conn._acquired_per_host[key].add(proto)

    conn._release(key, proto)
    assert conn._release_waiter.called
    assert conn._conns[key][0][0] == proto
    assert conn._conns[key][0][1] == pytest.approx(loop.time(), abs=0.1)
    assert not conn._cleanup_closed_transports
    conn.close()


def test_release_ssl_transport(loop, ssl_key):
    conn = aiohttp.BaseConnector(loop=loop, enable_cleanup_closed=True)
    conn._release_waiter = mock.Mock()

    proto = mock.Mock()
    conn._acquired.add(proto)
    conn._acquired_per_host[ssl_key].add(proto)

    conn._release(ssl_key, proto, should_close=True)
    assert conn._cleanup_closed_transports == [proto.close.return_value]
    conn.close()


def test_release_already_closed(loop):
    conn = aiohttp.BaseConnector(loop=loop)

    proto = mock.Mock()
    key = 1
    conn._acquired.add(proto)
    conn.close()

    conn._release_waiters = mock.Mock()
    conn._release_acquired = mock.Mock()

    conn._release(key, proto)
    assert not conn._release_waiters.called
    assert not conn._release_acquired.called


def test_release_waiter(loop, key, key2):
    # limit is 0
    conn = aiohttp.BaseConnector(limit=0, loop=loop)
    w = mock.Mock()
    w.done.return_value = False
    conn._waiters[key].append(w)
    conn._release_waiter()
    assert len(conn._waiters) == 1
    assert not w.done.called
    conn.close()

    # release first available
    conn = aiohttp.BaseConnector(loop=loop)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key].append(w2)
    conn._waiters[key2].append(w1)
    conn._release_waiter()
    assert (w1.set_result.called and not w2.set_result.called or
            not w1.set_result.called and w2.set_result.called)
    conn.close()

    # limited available
    conn = aiohttp.BaseConnector(loop=loop, limit=1)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key] = [w1, w2]
    conn._release_waiter()
    assert w1.set_result.called
    assert not w2.set_result.called
    conn.close()

    # limited available
    conn = aiohttp.BaseConnector(loop=loop, limit=1)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = True
    w2.done.return_value = False
    conn._waiters[key] = [w1, w2]
    conn._release_waiter()
    assert not w1.set_result.called
    assert not w2.set_result.called
    conn.close()


def test_release_waiter_per_host(loop, key, key2):
    # no limit
    conn = aiohttp.BaseConnector(loop=loop, limit=0, limit_per_host=2)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key] = [w1]
    conn._waiters[key2] = [w2]
    conn._release_waiter()
    assert ((w1.set_result.called and not w2.set_result.called) or
            (not w1.set_result.called and w2.set_result.called))
    conn.close()


def test_release_close(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    proto = mock.Mock(should_close=True)

    key = ('localhost', 80, False)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert not conn._conns
    assert proto.close.called


@asyncio.coroutine
def test_tcp_connector_resolve_host(loop):
    conn = aiohttp.TCPConnector(loop=loop, use_dns_cache=True)

    res = yield from conn._resolve_host('localhost', 8080)
    assert res
    for rec in res:
        if rec['family'] == socket.AF_INET:
            assert rec['host'] == '127.0.0.1'
            assert rec['hostname'] == 'localhost'
            assert rec['port'] == 8080
        elif rec['family'] == socket.AF_INET6:
            assert rec['hostname'] == 'localhost'
            assert rec['port'] == 8080
            if platform.system() == 'Darwin':
                assert rec['host'] in ('::1', 'fe80::1', 'fe80::1%lo0')
            else:
                assert rec['host'] == '::1'


@asyncio.coroutine
def dns_response():
    return ["127.0.0.1"]


@asyncio.coroutine
def test_tcp_connector_dns_cache_not_expired(loop):
    with mock.patch('aiohttp.connector.DefaultResolver') as m_resolver:
        conn = aiohttp.TCPConnector(
            loop=loop,
            use_dns_cache=True,
            ttl_dns_cache=10
        )
        m_resolver().resolve.return_value = dns_response()
        yield from conn._resolve_host('localhost', 8080)
        yield from conn._resolve_host('localhost', 8080)
        m_resolver().resolve.assert_called_once_with(
            'localhost',
            8080,
            family=0
        )


@asyncio.coroutine
def test_tcp_connector_dns_cache_forever(loop):
    with mock.patch('aiohttp.connector.DefaultResolver') as m_resolver:
        conn = aiohttp.TCPConnector(
            loop=loop,
            use_dns_cache=True,
            ttl_dns_cache=10
        )
        m_resolver().resolve.return_value = dns_response()
        yield from conn._resolve_host('localhost', 8080)
        yield from conn._resolve_host('localhost', 8080)
        m_resolver().resolve.assert_called_once_with(
            'localhost',
            8080,
            family=0
        )


@asyncio.coroutine
def test_tcp_connector_use_dns_cache_disabled(loop):
    with mock.patch('aiohttp.connector.DefaultResolver') as m_resolver:
        conn = aiohttp.TCPConnector(loop=loop, use_dns_cache=False)
        m_resolver().resolve.return_value = dns_response()
        yield from conn._resolve_host('localhost', 8080)
        yield from conn._resolve_host('localhost', 8080)
        m_resolver().resolve.assert_has_calls([
            mock.call('localhost', 8080, family=0),
            mock.call('localhost', 8080, family=0)
        ])


def test_get_pop_empty_conns(loop):
    # see issue #473
    conn = aiohttp.BaseConnector(loop=loop)
    key = ('127.0.0.1', 80, False)
    conn._conns[key] = []
    proto = conn._get(key)
    assert proto is None
    assert not conn._conns


def test_release_close_do_not_add_to_pool(loop):
    # see issue #473
    conn = aiohttp.BaseConnector(loop=loop)

    key = ('127.0.0.1', 80, False)
    proto = mock.Mock(should_close=True)

    conn._acquired.add(proto)
    conn._release(key, proto)
    assert not conn._conns


def test_release_close_do_not_delete_existing_connections(loop):
    key = ('127.0.0.1', 80, False)
    proto1 = mock.Mock()

    conn = aiohttp.BaseConnector(loop=loop)
    conn._conns[key] = [(proto1, 1)]

    proto = mock.Mock(should_close=True)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert conn._conns[key] == [(proto1, 1)]
    assert proto.close.called
    conn.close()


def test_release_not_started(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    proto = mock.Mock(should_close=False)
    key = 1
    conn._acquired.add(proto)
    conn._release(key, proto)
    # assert conn._conns == {1: [(proto, 10)]}
    rec = conn._conns[1]
    assert rec[0][0] == proto
    assert rec[0][1] == pytest.approx(loop.time(), abs=0.01)
    assert not proto.close.called
    conn.close()


def test_release_not_opened(loop):
    conn = aiohttp.BaseConnector(loop=loop)

    proto = mock.Mock()
    key = ('localhost', 80, False)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert proto.close.called


@asyncio.coroutine
def test_connect(loop):
    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://host:80'), loop=loop)

    conn = aiohttp.BaseConnector(loop=loop)
    key = ('host', 80, False)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    connection = yield from conn.connect(req)
    assert not conn._create_connection.called
    assert connection._protocol is proto
    assert connection.transport is proto.transport
    assert isinstance(connection, Connection)
    connection.close()


@asyncio.coroutine
def test_connect_oserr(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    err = OSError(1, 'permission error')
    conn._create_connection.return_value.set_exception(err)

    with pytest.raises(aiohttp.ClientOSError) as ctx:
        req = mock.Mock()
        yield from conn.connect(req)
    assert 1 == ctx.value.errno
    assert ctx.value.strerror.startswith('Cannot connect to')
    assert ctx.value.strerror.endswith('[permission error]')


def test_ctor_cleanup():
    loop = mock.Mock()
    loop.time.return_value = 1.5
    conn = aiohttp.BaseConnector(
        loop=loop, keepalive_timeout=10, enable_cleanup_closed=True)
    assert conn._cleanup_handle is None
    assert conn._cleanup_closed_handle is not None


def test_cleanup():
    key = ('localhost', 80, False)
    testset = {
        key: [(mock.Mock(), 10),
              (mock.Mock(), 300)],
    }
    testset[key][0][0].is_connected.return_value = True
    testset[key][1][0].is_connected.return_value = False

    loop = mock.Mock()
    loop.time.return_value = 300
    conn = aiohttp.BaseConnector(loop=loop)
    conn._conns = testset
    existing_handle = conn._cleanup_handle = mock.Mock()

    conn._cleanup()
    assert existing_handle.cancel.called
    assert conn._conns == {}
    assert conn._cleanup_handle is not None


def test_cleanup_close_ssl_transport():
    proto = mock.Mock()
    key = ('localhost', 80, True)
    testset = {key: [(proto, 10)]}

    loop = mock.Mock()
    loop.time.return_value = 300
    conn = aiohttp.BaseConnector(loop=loop, enable_cleanup_closed=True)
    conn._conns = testset
    existing_handle = conn._cleanup_handle = mock.Mock()

    conn._cleanup()
    assert existing_handle.cancel.called
    assert conn._conns == {}
    assert conn._cleanup_closed_transports == [proto.close.return_value]


def test_cleanup2():
    testset = {1: [(mock.Mock(), 300)]}
    testset[1][0][0].is_connected.return_value = True

    loop = mock.Mock()
    loop.time.return_value = 300

    conn = aiohttp.BaseConnector(loop=loop, keepalive_timeout=10)
    conn._conns = testset
    conn._cleanup()
    assert conn._conns == testset

    assert conn._cleanup_handle is not None
    loop.call_at.assert_called_with(310, mock.ANY, mock.ANY)
    conn.close()


def test_cleanup3():
    key = ('localhost', 80, False)
    testset = {key: [(mock.Mock(), 290.1),
                     (mock.Mock(), 305.1)]}
    testset[key][0][0].is_connected.return_value = True

    loop = mock.Mock()
    loop.time.return_value = 308.5

    conn = aiohttp.BaseConnector(loop=loop, keepalive_timeout=10)
    conn._conns = testset

    conn._cleanup()
    assert conn._conns == {key: [testset[key][1]]}

    assert conn._cleanup_handle is not None
    loop.call_at.assert_called_with(319, mock.ANY, mock.ANY)
    conn.close()


def test_cleanup_closed(loop, mocker):
    if not hasattr(loop, '__dict__'):
        pytest.skip("can not override loop attributes")

    mocker.spy(loop, 'call_at')
    conn = aiohttp.BaseConnector(loop=loop, enable_cleanup_closed=True)

    tr = mock.Mock()
    conn._cleanup_closed_handle = cleanup_closed_handle = mock.Mock()
    conn._cleanup_closed_transports = [tr]
    conn._cleanup_closed()
    assert tr.abort.called
    assert not conn._cleanup_closed_transports
    assert loop.call_at.called
    assert cleanup_closed_handle.cancel.called


def test_cleanup_closed_disabled(loop, mocker):
    conn = aiohttp.BaseConnector(
        loop=loop, enable_cleanup_closed=False)

    tr = mock.Mock()
    conn._cleanup_closed_transports = [tr]
    conn._cleanup_closed()
    assert tr.abort.called
    assert not conn._cleanup_closed_transports


def test_tcp_connector_ctor(loop):
    conn = aiohttp.TCPConnector(loop=loop)
    assert conn.verify_ssl
    assert conn.fingerprint is None

    assert conn.use_dns_cache
    assert conn.family == 0
    assert conn.cached_hosts == {}


def test_tcp_connector_ctor_fingerprint_valid(loop):
    valid = b'\xa2\x06G\xad\xaa\xf5\xd8\\J\x99^by;\x06='
    # md5 and sha1 are deprecated
    with pytest.warns(DeprecationWarning):
        conn = aiohttp.TCPConnector(loop=loop, fingerprint=valid)
    assert conn.fingerprint == valid


def test_tcp_connector_fingerprint_invalid(loop):
    invalid = b'\x00'
    with pytest.raises(ValueError):
        aiohttp.TCPConnector(loop=loop, fingerprint=invalid)


def test_tcp_connector_clear_dns_cache(loop):
    conn = aiohttp.TCPConnector(loop=loop)
    hosts = ['a', 'b']
    conn._cached_hosts.add(('localhost', 123), hosts)
    conn._cached_hosts.add(('localhost', 124), hosts)
    conn.clear_dns_cache('localhost', 123)
    assert ('localhost', 123) not in conn.cached_hosts
    conn.clear_dns_cache('localhost', 123)
    assert ('localhost', 123) not in conn.cached_hosts
    conn.clear_dns_cache()
    assert conn.cached_hosts == {}


def test_tcp_connector_clear_dns_cache_bad_args(loop):
    conn = aiohttp.TCPConnector(loop=loop)
    with pytest.raises(ValueError):
        conn.clear_dns_cache('localhost')


def test_ambigous_verify_ssl_and_ssl_context(loop):
    with pytest.raises(ValueError):
        aiohttp.TCPConnector(
            verify_ssl=False,
            ssl_context=ssl.SSLContext(ssl.PROTOCOL_SSLv23),
            loop=loop)


def test_dont_recreate_ssl_context(loop):
    conn = aiohttp.TCPConnector(loop=loop)
    ctx = conn.ssl_context
    assert ctx is conn.ssl_context


def test_respect_precreated_ssl_context(loop):
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    conn = aiohttp.TCPConnector(loop=loop, ssl_context=ctx)
    assert ctx is conn.ssl_context


def test_close_twice(loop):
    proto = mock.Mock()

    conn = aiohttp.BaseConnector(loop=loop)
    conn._conns[1] = [(proto, object())]
    conn.close()

    assert not conn._conns
    assert proto.close.called
    assert conn.closed

    conn._conns = 'Invalid'  # fill with garbage
    conn.close()
    assert conn.closed


def test_close_cancels_cleanup_handle(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    conn._release(1, mock.Mock(should_close=False))
    assert conn._cleanup_handle is not None
    conn.close()
    assert conn._cleanup_handle is None


def test_close_abort_closed_transports(loop):
    tr = mock.Mock()

    conn = aiohttp.BaseConnector(loop=loop)
    conn._cleanup_closed_transports.append(tr)
    conn.close()

    assert not conn._cleanup_closed_transports
    assert tr.abort.called
    assert conn.closed


def test_close_cancels_cleanup_closed_handle(loop):
    conn = aiohttp.BaseConnector(loop=loop, enable_cleanup_closed=True)
    assert conn._cleanup_closed_handle is not None
    conn.close()
    assert conn._cleanup_closed_handle is None


def test_ctor_with_default_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    conn = aiohttp.BaseConnector()
    assert loop is conn._loop
    loop.close()


@asyncio.coroutine
def test_connect_with_limit(loop, key):
    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://localhost1:80'),
                        loop=loop,
                        response_class=mock.Mock())

    conn = aiohttp.BaseConnector(loop=loop, limit=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    connection1 = yield from conn.connect(req)
    assert connection1._protocol == proto

    assert 1 == len(conn._acquired)
    assert proto in conn._acquired
    assert key in conn._acquired_per_host
    assert proto in conn._acquired_per_host[key]

    acquired = False

    @asyncio.coroutine
    def f():
        nonlocal acquired
        connection2 = yield from conn.connect(req)
        acquired = True
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        connection2.release()

    task = helpers.ensure_future(f(), loop=loop)

    yield from asyncio.sleep(0.01, loop=loop)
    assert not acquired
    connection1.release()
    yield from asyncio.sleep(0, loop=loop)
    assert acquired
    yield from task
    conn.close()


@asyncio.coroutine
def test_connect_with_limit_and_limit_per_host(loop, key):
    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://localhost1:80'), loop=loop)

    conn = aiohttp.BaseConnector(loop=loop, limit=1000, limit_per_host=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    acquired = False
    connection1 = yield from conn.connect(req)

    @asyncio.coroutine
    def f():
        nonlocal acquired
        connection2 = yield from conn.connect(req)
        acquired = True
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        connection2.release()

    task = helpers.ensure_future(f(), loop=loop)

    yield from asyncio.sleep(0.01, loop=loop)
    assert not acquired
    connection1.release()
    yield from asyncio.sleep(0, loop=loop)
    assert acquired
    yield from task
    conn.close()


@asyncio.coroutine
def test_connect_with_no_limit_and_limit_per_host(loop, key):
    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://localhost1:80'), loop=loop)

    conn = aiohttp.BaseConnector(loop=loop, limit=0, limit_per_host=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    acquired = False
    connection1 = yield from conn.connect(req)

    @asyncio.coroutine
    def f():
        nonlocal acquired
        connection2 = yield from conn.connect(req)
        acquired = True
        connection2.release()

    task = helpers.ensure_future(f(), loop=loop)

    yield from asyncio.sleep(0.01, loop=loop)
    assert not acquired
    connection1.release()
    yield from asyncio.sleep(0, loop=loop)
    assert acquired
    yield from task
    conn.close()


@asyncio.coroutine
def test_connect_with_no_limits(loop, key):
    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://localhost1:80'), loop=loop)

    conn = aiohttp.BaseConnector(loop=loop, limit=0, limit_per_host=0)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    acquired = False
    connection1 = yield from conn.connect(req)

    @asyncio.coroutine
    def f():
        nonlocal acquired
        connection2 = yield from conn.connect(req)
        acquired = True
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        connection2.release()

    task = helpers.ensure_future(f(), loop=loop)

    yield from asyncio.sleep(0.01, loop=loop)
    assert acquired
    connection1.release()
    yield from task
    conn.close()


@asyncio.coroutine
def test_connect_with_limit_cancelled(loop):

    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://host:80'), loop=loop)

    conn = aiohttp.BaseConnector(loop=loop, limit=1)
    key = ('host', 80, False)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    connection = yield from conn.connect(req)
    assert connection._protocol == proto
    assert connection.transport == proto.transport

    assert 1 == len(conn._acquired)

    with pytest.raises(asyncio.TimeoutError):
        # limit exhausted
        yield from asyncio.wait_for(conn.connect(req), 0.01,
                                    loop=loop)
    connection.close()


@asyncio.coroutine
def test_connect_with_capacity_release_waiters(loop):

    def check_with_exc(err):
        conn = aiohttp.BaseConnector(limit=1, loop=loop)
        conn._create_connection = mock.Mock()
        conn._create_connection.return_value = \
            helpers.create_future(loop)
        conn._create_connection.return_value.set_exception(err)

        with pytest.raises(Exception):
            req = mock.Mock()
            yield from conn.connect(req)

        assert not conn._waiters

    check_with_exc(OSError(1, 'permission error'))
    check_with_exc(RuntimeError())
    check_with_exc(asyncio.TimeoutError())


@asyncio.coroutine
def test_connect_with_limit_concurrent(loop):
    proto = mock.Mock()
    proto.should_close = False
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://host:80'), loop=loop)

    max_connections = 2
    num_connections = 0

    conn = aiohttp.BaseConnector(limit=max_connections, loop=loop)

    # Use a real coroutine for _create_connection; a mock would mask
    # problems that only happen when the method yields.

    @asyncio.coroutine
    def create_connection(req):
        nonlocal num_connections
        num_connections += 1
        yield from asyncio.sleep(0, loop=loop)

        # Make a new transport mock each time because acquired
        # transports are stored in a set. Reusing the same object
        # messes with the count.
        proto = mock.Mock(should_close=False)
        proto.is_connected.return_value = True

        return proto

    conn._create_connection = create_connection

    # Simulate something like a crawler. It opens a connection, does
    # something with it, closes it, then creates tasks that make more
    # connections and waits for them to finish. The crawler is started
    # with multiple concurrent requests and stops when it hits a
    # predefined maximum number of requests.

    max_requests = 10
    num_requests = 0
    start_requests = max_connections + 1

    @asyncio.coroutine
    def f(start=True):
        nonlocal num_requests
        if num_requests == max_requests:
            return
        num_requests += 1
        if not start:
            connection = yield from conn.connect(req)
            yield from asyncio.sleep(0, loop=loop)
            connection.release()
        tasks = [
            helpers.ensure_future(f(start=False), loop=loop)
            for i in range(start_requests)
        ]
        yield from asyncio.wait(tasks, loop=loop)

    yield from f()
    conn.close()

    assert max_connections == num_connections


@asyncio.coroutine
def test_close_with_acquired_connection(loop):
    proto = mock.Mock()
    proto.is_connected.return_value = True

    req = ClientRequest('GET', URL('http://host:80'), loop=loop)

    conn = aiohttp.BaseConnector(loop=loop, limit=1)
    key = ('host', 80, False)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = helpers.create_future(loop)
    conn._create_connection.return_value.set_result(proto)

    connection = yield from conn.connect(req)

    assert 1 == len(conn._acquired)
    conn.close()
    assert 0 == len(conn._acquired)
    assert conn.closed
    proto.close.assert_called_with()

    assert not connection.closed
    connection.close()
    assert connection.closed


def test_default_force_close(loop):
    connector = aiohttp.BaseConnector(loop=loop)
    assert not connector.force_close


def test_limit_property(loop):
    conn = aiohttp.BaseConnector(loop=loop, limit=15)
    assert 15 == conn.limit

    conn.close()


def test_limit_per_host_property(loop):
    conn = aiohttp.BaseConnector(loop=loop, limit_per_host=15)
    assert 15 == conn.limit_per_host

    conn.close()


def test_limit_property_default(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    assert conn.limit == 100
    conn.close()


def test_limit_per_host_property_default(loop):
    conn = aiohttp.BaseConnector(loop=loop)
    assert conn.limit_per_host == 0
    conn.close()


def test_force_close_and_explicit_keep_alive(loop):
    with pytest.raises(ValueError):
        aiohttp.BaseConnector(loop=loop, keepalive_timeout=30,
                              force_close=True)

    conn = aiohttp.BaseConnector(loop=loop, force_close=True,
                                 keepalive_timeout=None)
    assert conn

    conn = aiohttp.BaseConnector(loop=loop, force_close=True)

    assert conn


@asyncio.coroutine
def test_tcp_connector(test_client, loop):
    @asyncio.coroutine
    def handler(request):
        return web.HTTPOk()

    app = web.Application()
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    r = yield from client.get('/')
    assert r.status == 200


def test_default_use_dns_cache(loop):
    conn = aiohttp.TCPConnector(loop=loop)
    assert conn.use_dns_cache


class TestHttpClientConnector(unittest.TestCase):

    def setUp(self):
        self.handler = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()
        gc.collect()

    @asyncio.coroutine
    def create_server(self, method, path, handler):
        app = web.Application()
        app.router.add_route(method, path, handler)

        port = unused_port()
        self.handler = app.make_handler(loop=self.loop, tcp_keepalive=False)
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    @asyncio.coroutine
    def create_unix_server(self, method, path, handler):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        app = web.Application()
        app.router.add_route(method, path, handler)

        self.handler = app.make_handler(
            loop=self.loop, tcp_keepalive=False, access_log=None)
        sock_path = os.path.join(tmpdir, 'socket.sock')
        srv = yield from self.loop.create_unix_server(
            self.handler, sock_path)
        url = "http://127.0.0.1" + path
        self.addCleanup(srv.close)
        return app, srv, url, sock_path

    def test_tcp_connector_uses_provided_local_addr(self):
        @asyncio.coroutine
        def handler(request):
            return web.HTTPOk()

        app, srv, url = self.loop.run_until_complete(
            self.create_server('get', '/', handler)
        )

        port = unused_port()
        conn = aiohttp.TCPConnector(loop=self.loop,
                                    local_addr=('127.0.0.1', port))

        session = aiohttp.ClientSession(connector=conn)

        r = self.loop.run_until_complete(
            session.request('get', url)
        )

        r.release()
        first_conn = next(iter(conn._conns.values()))[0][0]
        self.assertEqual(
            first_conn.transport._sock.getsockname(), ('127.0.0.1', port))
        r.close()
        session.close()
        conn.close()

    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'requires unix')
    def test_unix_connector(self):
        @asyncio.coroutine
        def handler(request):
            return web.HTTPOk()

        app, srv, url, sock_path = self.loop.run_until_complete(
            self.create_unix_server('get', '/', handler))

        connector = aiohttp.UnixConnector(sock_path, loop=self.loop)
        self.assertEqual(sock_path, connector.path)

        session = client.ClientSession(
            connector=connector, loop=self.loop)
        r = self.loop.run_until_complete(
            session.request('get', url))
        self.assertEqual(r.status, 200)
        r.close()
        session.close()

    def test_resolver_not_called_with_address_is_ip(self):
        resolver = mock.MagicMock()
        connector = aiohttp.TCPConnector(resolver=resolver, loop=self.loop)

        req = ClientRequest('GET',
                            URL('http://127.0.0.1:{}'.format(unused_port())),
                            loop=self.loop,
                            response_class=mock.Mock())

        with self.assertRaises(OSError):
            self.loop.run_until_complete(connector.connect(req))

        resolver.resolve.assert_not_called()


class TestDNSCacheTable:

    @pytest.fixture
    def dns_cache_table(self):
        return _DNSCacheTable()

    def test_addrs(self, dns_cache_table):
        dns_cache_table.add('localhost', ['127.0.0.1'])
        dns_cache_table.add('foo', ['127.0.0.2'])
        assert dns_cache_table.addrs == {
            'localhost': ['127.0.0.1'],
            'foo': ['127.0.0.2']
        }

    def test_remove(self, dns_cache_table):
        dns_cache_table.add('localhost', ['127.0.0.1'])
        dns_cache_table.remove('localhost')
        assert dns_cache_table.addrs == {}

    def test_clear(self, dns_cache_table):
        dns_cache_table.add('localhost', ['127.0.0.1'])
        dns_cache_table.clear()
        assert dns_cache_table.addrs == {}

    def test_not_expired_ttl_None(self, dns_cache_table):
        dns_cache_table.add('localhost', ['127.0.0.1'])
        assert not dns_cache_table.expired('localhost')

    def test_not_expired_ttl(self):
        dns_cache_table = _DNSCacheTable(ttl=0.1)
        dns_cache_table.add('localhost', ['127.0.0.1'])
        assert not dns_cache_table.expired('localhost')

    @asyncio.coroutine
    def test_expired_ttl(self, loop):
        dns_cache_table = _DNSCacheTable(ttl=0.01)
        dns_cache_table.add('localhost', ['127.0.0.1'])
        yield from asyncio.sleep(0.01, loop=loop)
        assert dns_cache_table.expired('localhost')

    def test_next_addrs(self, dns_cache_table):
        dns_cache_table.add('foo', ['127.0.0.1', '127.0.0.2'])

        # max elements returned are the full list of addrs
        addrs = list(dns_cache_table.next_addrs('foo'))
        assert addrs == ['127.0.0.1', '127.0.0.2']

        # different calls to next_addrs return the hosts using
        # a round robin strategy.
        addrs = dns_cache_table.next_addrs('foo')
        assert next(addrs) == '127.0.0.1'
        addrs = dns_cache_table.next_addrs('foo')
        assert next(addrs) == '127.0.0.2'
