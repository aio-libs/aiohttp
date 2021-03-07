# type: ignore
# Tests of http client with custom Connector

import asyncio
import gc
import hashlib
import platform
import socket
import ssl
import sys
import uuid
from collections import deque
from typing import Any, Optional
from unittest import mock

import pytest
from conftest import needs_unix
from yarl import URL

import aiohttp
from aiohttp import client, web
from aiohttp.client import ClientRequest, ClientTimeout
from aiohttp.client_reqrep import ConnectionKey
from aiohttp.connector import Connection, TCPConnector, _DNSCacheTable
from aiohttp.locks import EventResultOrError
from aiohttp.test_utils import make_mocked_coro, unused_port
from aiohttp.tracing import Trace


@pytest.fixture()
def key():
    # Connection key
    return ConnectionKey("localhost", 80, False, None, None, None, None)


@pytest.fixture
def key2():
    # Connection key
    return ConnectionKey("localhost", 80, False, None, None, None, None)


@pytest.fixture
def ssl_key():
    # Connection key
    return ConnectionKey("localhost", 80, True, None, None, None, None)


@pytest.fixture
def unix_server(loop: Any, unix_sockname: Any) -> None:
    runners = []

    async def go(app):
        runner = web.AppRunner(app)
        runners.append(runner)
        await runner.setup()
        site = web.UnixSite(runner, unix_sockname)
        await site.start()

    yield go

    for runner in runners:
        loop.run_until_complete(runner.cleanup())


@pytest.fixture
def named_pipe_server(proactor_loop: Any, pipe_name: Any) -> None:
    runners = []

    async def go(app):
        runner = web.AppRunner(app)
        runners.append(runner)
        await runner.setup()
        site = web.NamedPipeSite(runner, pipe_name)
        await site.start()

    yield go

    for runner in runners:
        proactor_loop.run_until_complete(runner.cleanup())


def create_mocked_conn(conn_closing_result: Optional[Any] = None, **kwargs: Any):
    assert "loop" not in kwargs
    loop = asyncio.get_event_loop()
    proto = mock.Mock(**kwargs)
    proto.closed = loop.create_future()
    proto.closed.set_result(conn_closing_result)
    return proto


def test_connection_del(loop: Any) -> None:
    connector = mock.Mock()
    key = mock.Mock()
    protocol = mock.Mock()
    loop.set_debug(0)
    conn = Connection(connector, key, protocol, loop=loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    connector._release.assert_called_with(key, protocol, should_close=True)
    msg = {
        "message": mock.ANY,
        "client_connection": mock.ANY,
    }
    exc_handler.assert_called_with(loop, msg)


def test_connection_del_loop_debug(loop: Any) -> None:
    connector = mock.Mock()
    key = mock.Mock()
    protocol = mock.Mock()
    loop.set_debug(1)
    conn = Connection(connector, key, protocol, loop=loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    msg = {
        "message": mock.ANY,
        "client_connection": mock.ANY,
        "source_traceback": mock.ANY,
    }
    exc_handler.assert_called_with(loop, msg)


def test_connection_del_loop_closed(loop: Any) -> None:
    connector = mock.Mock()
    key = mock.Mock()
    protocol = mock.Mock()
    loop.set_debug(1)
    conn = Connection(connector, key, protocol, loop=loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)
    loop.close()

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    assert not connector._release.called
    assert not exc_handler.called


async def test_del(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    proto = create_mocked_conn(loop, should_close=False)
    conn._release("a", proto)
    conns_impl = conn._conns

    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    assert not conns_impl
    proto.close.assert_called_with()
    msg = {
        "connector": mock.ANY,  # conn was deleted
        "connections": mock.ANY,
        "message": "Unclosed connector",
    }
    if loop.get_debug():
        msg["source_traceback"] = mock.ANY
    exc_handler.assert_called_with(loop, msg)


@pytest.mark.xfail
async def test_del_with_scheduled_cleanup(loop: Any) -> None:
    loop.set_debug(True)
    conn = aiohttp.BaseConnector(keepalive_timeout=0.01)
    transp = create_mocked_conn(loop)
    conn._conns["a"] = [(transp, 123)]

    conns_impl = conn._conns
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        # obviously doesn't deletion because loop has a strong
        # reference to connector's instance method, isn't it?
        del conn
        await asyncio.sleep(0.01, loop=loop)
        gc.collect()

    assert not conns_impl
    transp.close.assert_called_with()
    msg = {"connector": mock.ANY, "message": "Unclosed connector"}  # conn was deleted
    if loop.get_debug():
        msg["source_traceback"] = mock.ANY
    exc_handler.assert_called_with(loop, msg)


@pytest.mark.skipif(
    sys.implementation.name != "cpython", reason="CPython GC is required for the test"
)
def test_del_with_closed_loop(loop: Any) -> None:
    async def make_conn():
        return aiohttp.BaseConnector()

    conn = loop.run_until_complete(make_conn())
    transp = create_mocked_conn(loop)
    conn._conns["a"] = [(transp, 123)]

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


async def test_del_empty_connector(loop: Any) -> None:
    conn = aiohttp.BaseConnector()

    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    del conn

    assert not exc_handler.called


async def test_create_conn() -> None:
    conn = aiohttp.BaseConnector()
    with pytest.raises(NotImplementedError):
        await conn._create_connection(object(), [], object())


async def test_async_context_manager(loop: Any) -> None:
    conn = aiohttp.BaseConnector()

    async with conn as c:
        assert conn is c

    assert conn.closed


async def test_close() -> None:
    proto = create_mocked_conn()

    conn = aiohttp.BaseConnector()
    assert not conn.closed
    conn._conns[("host", 8080, False)] = [(proto, object())]
    await conn.close()

    assert not conn._conns
    assert proto.close.called
    assert conn.closed


async def test_get(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    assert conn._get(1) is None

    proto = create_mocked_conn(loop)
    conn._conns[1] = [(proto, loop.time())]
    assert conn._get(1) == proto
    await conn.close()


async def test_get_unconnected_proto(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    key = ConnectionKey("localhost", 80, False, None, None, None, None)
    assert conn._get(key) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = [(proto, loop.time())]
    assert conn._get(key) == proto

    assert conn._get(key) is None
    conn._conns[key] = [(proto, loop.time())]
    proto.is_connected = lambda *args: False
    assert conn._get(key) is None
    await conn.close()


async def test_get_unconnected_proto_ssl(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    key = ConnectionKey("localhost", 80, True, None, None, None, None)
    assert conn._get(key) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = [(proto, loop.time())]
    assert conn._get(key) == proto

    assert conn._get(key) is None
    conn._conns[key] = [(proto, loop.time())]
    proto.is_connected = lambda *args: False
    assert conn._get(key) is None
    await conn.close()


async def test_get_expired(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    key = ConnectionKey("localhost", 80, False, None, None, None, None)
    assert conn._get(key) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = [(proto, loop.time() - 1000)]
    assert conn._get(key) is None
    assert not conn._conns
    await conn.close()


async def test_get_expired_ssl(loop: Any) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    key = ConnectionKey("localhost", 80, True, None, None, None, None)
    assert conn._get(key) is None

    proto = create_mocked_conn(loop)
    transport = proto.transport
    conn._conns[key] = [(proto, loop.time() - 1000)]
    assert conn._get(key) is None
    assert not conn._conns
    assert conn._cleanup_closed_transports == [transport]
    await conn.close()


async def test_release_acquired(key: Any) -> None:
    proto = create_mocked_conn()
    conn = aiohttp.BaseConnector(limit=5)
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

    await conn.close()


async def test_release_acquired_closed(key: Any) -> None:
    proto = create_mocked_conn()
    conn = aiohttp.BaseConnector(limit=5)
    conn._release_waiter = mock.Mock()

    conn._acquired.add(proto)
    conn._acquired_per_host[key].add(proto)
    conn._closed = True
    conn._release_acquired(key, proto)
    assert 1 == len(conn._acquired)
    assert 1 == len(conn._acquired_per_host[key])
    assert not conn._release_waiter.called
    await conn.close()


async def test_release(loop: Any, key: Any) -> None:
    conn = aiohttp.BaseConnector()
    conn._release_waiter = mock.Mock()

    proto = create_mocked_conn(loop, should_close=False)

    conn._acquired.add(proto)
    conn._acquired_per_host[key].add(proto)

    conn._release(key, proto)
    assert conn._release_waiter.called
    assert conn._cleanup_handle is not None
    assert conn._conns[key][0][0] == proto
    assert conn._conns[key][0][1] == pytest.approx(loop.time(), abs=0.1)
    assert not conn._cleanup_closed_transports
    await conn.close()


async def test_release_ssl_transport(loop: Any, ssl_key: Any) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    conn._release_waiter = mock.Mock()

    proto = create_mocked_conn(loop)
    transport = proto.transport
    conn._acquired.add(proto)
    conn._acquired_per_host[ssl_key].add(proto)

    conn._release(ssl_key, proto, should_close=True)
    assert conn._cleanup_closed_transports == [transport]
    await conn.close()


async def test_release_already_closed() -> None:
    conn = aiohttp.BaseConnector()

    proto = create_mocked_conn()
    key = 1
    conn._acquired.add(proto)
    await conn.close()

    conn._release_waiters = mock.Mock()
    conn._release_acquired = mock.Mock()

    conn._release(key, proto)
    assert not conn._release_waiters.called
    assert not conn._release_acquired.called


async def test_release_waiter_no_limit(loop: Any, key: Any, key2: Any) -> None:
    # limit is 0
    conn = aiohttp.BaseConnector(limit=0)
    w = mock.Mock()
    w.done.return_value = False
    conn._waiters[key].append(w)
    conn._release_waiter()
    assert len(conn._waiters[key]) == 0
    assert w.done.called
    await conn.close()


async def test_release_waiter_first_available(loop: Any, key: Any, key2: Any) -> None:
    conn = aiohttp.BaseConnector()
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key].append(w2)
    conn._waiters[key2].append(w1)
    conn._release_waiter()
    assert (
        w1.set_result.called
        and not w2.set_result.called
        or not w1.set_result.called
        and w2.set_result.called
    )
    await conn.close()


async def test_release_waiter_release_first(loop: Any, key: Any, key2: Any) -> None:
    conn = aiohttp.BaseConnector(limit=1)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key] = deque([w1, w2])
    conn._release_waiter()
    assert w1.set_result.called
    assert not w2.set_result.called
    await conn.close()


async def test_release_waiter_skip_done_waiter(loop: Any, key: Any, key2: Any) -> None:
    conn = aiohttp.BaseConnector(limit=1)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = True
    w2.done.return_value = False
    conn._waiters[key] = deque([w1, w2])
    conn._release_waiter()
    assert not w1.set_result.called
    assert w2.set_result.called
    await conn.close()


async def test_release_waiter_per_host(loop: Any, key: Any, key2: Any) -> None:
    # no limit
    conn = aiohttp.BaseConnector(limit=0, limit_per_host=2)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key] = deque([w1])
    conn._waiters[key2] = deque([w2])
    conn._release_waiter()
    assert (w1.set_result.called and not w2.set_result.called) or (
        not w1.set_result.called and w2.set_result.called
    )
    await conn.close()


async def test_release_waiter_no_available(loop: Any, key: Any, key2: Any) -> None:
    # limit is 0
    conn = aiohttp.BaseConnector(limit=0)
    w = mock.Mock()
    w.done.return_value = False
    conn._waiters[key].append(w)
    conn._available_connections = mock.Mock(return_value=0)
    conn._release_waiter()
    assert len(conn._waiters) == 1
    assert not w.done.called
    await conn.close()


async def test_release_close(key: Any) -> None:
    conn = aiohttp.BaseConnector()
    proto = create_mocked_conn(should_close=True)

    conn._acquired.add(proto)
    conn._release(key, proto)
    assert not conn._conns
    assert proto.close.called


async def test__drop_acquire_per_host1(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    conn._drop_acquired_per_host(123, 456)
    assert len(conn._acquired_per_host) == 0


async def test__drop_acquire_per_host2(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    conn._acquired_per_host[123].add(456)
    conn._drop_acquired_per_host(123, 456)
    assert len(conn._acquired_per_host) == 0


async def test__drop_acquire_per_host3(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    conn._acquired_per_host[123].add(456)
    conn._acquired_per_host[123].add(789)
    conn._drop_acquired_per_host(123, 456)
    assert len(conn._acquired_per_host) == 1
    assert conn._acquired_per_host[123] == {789}


async def test_tcp_connector_certificate_error(loop: Any) -> None:
    req = ClientRequest("GET", URL("https://127.0.0.1:443"), loop=loop)

    async def certificate_error(*args, **kwargs):
        raise ssl.CertificateError

    conn = aiohttp.TCPConnector()
    conn._loop.create_connection = certificate_error

    with pytest.raises(aiohttp.ClientConnectorCertificateError) as ctx:
        await conn.connect(req, [], ClientTimeout())

    assert isinstance(ctx.value, ssl.CertificateError)
    assert isinstance(ctx.value.certificate_error, ssl.CertificateError)
    assert isinstance(ctx.value, aiohttp.ClientSSLError)


async def test_tcp_connector_multiple_hosts_errors(loop: Any) -> None:
    conn = aiohttp.TCPConnector()

    ip1 = "192.168.1.1"
    ip2 = "192.168.1.2"
    ip3 = "192.168.1.3"
    ip4 = "192.168.1.4"
    ip5 = "192.168.1.5"
    ips = [ip1, ip2, ip3, ip4, ip5]
    ips_tried = []

    fingerprint = hashlib.sha256(b"foo").digest()

    req = ClientRequest(
        "GET",
        URL("https://mocked.host"),
        ssl=aiohttp.Fingerprint(fingerprint),
        loop=loop,
    )

    async def _resolve_host(host, port, traces=None):
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in ips
        ]

    conn._resolve_host = _resolve_host

    os_error = certificate_error = ssl_error = fingerprint_error = False
    connected = False

    async def create_connection(*args, **kwargs):
        nonlocal os_error, certificate_error, ssl_error, fingerprint_error
        nonlocal connected

        ip = args[1]

        ips_tried.append(ip)

        if ip == ip1:
            os_error = True
            raise OSError

        if ip == ip2:
            certificate_error = True
            raise ssl.CertificateError

        if ip == ip3:
            ssl_error = True
            raise ssl.SSLError

        if ip == ip4:
            fingerprint_error = True
            tr = create_mocked_conn(loop)
            pr = create_mocked_conn(loop)

            def get_extra_info(param):
                if param == "sslcontext":
                    return True

                if param == "ssl_object":
                    s = create_mocked_conn(loop)
                    s.getpeercert.return_value = b"not foo"
                    return s

                if param == "peername":
                    return ("192.168.1.5", 12345)

                assert False, param

            tr.get_extra_info = get_extra_info
            return tr, pr

        if ip == ip5:
            connected = True
            tr = create_mocked_conn(loop)
            pr = create_mocked_conn(loop)

            def get_extra_info(param):
                if param == "sslcontext":
                    return True

                if param == "ssl_object":
                    s = create_mocked_conn(loop)
                    s.getpeercert.return_value = b"foo"
                    return s

                assert False

            tr.get_extra_info = get_extra_info
            return tr, pr

        assert False

    conn._loop.create_connection = create_connection

    established_connection = await conn.connect(req, [], ClientTimeout())
    assert ips == ips_tried

    assert os_error
    assert certificate_error
    assert ssl_error
    assert fingerprint_error
    assert connected

    established_connection.close()


async def test_tcp_connector_resolve_host(loop: Any) -> None:
    conn = aiohttp.TCPConnector(use_dns_cache=True)

    res = await conn._resolve_host("localhost", 8080)
    assert res
    for rec in res:
        if rec["family"] == socket.AF_INET:
            assert rec["host"] == "127.0.0.1"
            assert rec["hostname"] == "localhost"
            assert rec["port"] == 8080
        elif rec["family"] == socket.AF_INET6:
            assert rec["hostname"] == "localhost"
            assert rec["port"] == 8080
            if platform.system() == "Darwin":
                assert rec["host"] in ("::1", "fe80::1", "fe80::1%lo0")
            else:
                assert rec["host"] == "::1"


@pytest.fixture
def dns_response(loop: Any):
    async def coro():
        # simulates a network operation
        await asyncio.sleep(0)
        return ["127.0.0.1"]

    return coro


async def test_tcp_connector_dns_cache_not_expired(
    loop: Any, dns_response: Any
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        await conn._resolve_host("localhost", 8080)
        await conn._resolve_host("localhost", 8080)
        m_resolver().resolve.assert_called_once_with("localhost", 8080, family=0)


async def test_tcp_connector_dns_cache_forever(loop: Any, dns_response: Any) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        await conn._resolve_host("localhost", 8080)
        await conn._resolve_host("localhost", 8080)
        m_resolver().resolve.assert_called_once_with("localhost", 8080, family=0)


async def test_tcp_connector_use_dns_cache_disabled(
    loop: Any, dns_response: Any
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=False)
        m_resolver().resolve.side_effect = [dns_response(), dns_response()]
        await conn._resolve_host("localhost", 8080)
        await conn._resolve_host("localhost", 8080)
        m_resolver().resolve.assert_has_calls(
            [
                mock.call("localhost", 8080, family=0),
                mock.call("localhost", 8080, family=0),
            ]
        )


async def test_tcp_connector_dns_throttle_requests(
    loop: Any, dns_response: Any
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        loop.create_task(conn._resolve_host("localhost", 8080))
        loop.create_task(conn._resolve_host("localhost", 8080))
        await asyncio.sleep(0)
        m_resolver().resolve.assert_called_once_with("localhost", 8080, family=0)


async def test_tcp_connector_dns_throttle_requests_exception_spread(loop: Any) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        e = Exception()
        m_resolver().resolve.side_effect = e
        r1 = loop.create_task(conn._resolve_host("localhost", 8080))
        r2 = loop.create_task(conn._resolve_host("localhost", 8080))
        await asyncio.sleep(0)
        assert r1.exception() == e
        assert r2.exception() == e


async def test_tcp_connector_dns_throttle_requests_cancelled_when_close(
    loop: Any, dns_response: Any
) -> None:

    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        loop.create_task(conn._resolve_host("localhost", 8080))
        f = loop.create_task(conn._resolve_host("localhost", 8080))

        await asyncio.sleep(0)
        await conn.close()

        with pytest.raises(asyncio.CancelledError):
            await f


@pytest.fixture
def dns_response_error(loop: Any):
    async def coro():
        # simulates a network operation
        await asyncio.sleep(0)
        raise socket.gaierror(-3, "Temporary failure in name resolution")

    return coro


async def test_tcp_connector_cancel_dns_error_captured(
    loop: Any, dns_response_error: Any
) -> None:

    exception_handler_called = False

    def exception_handler(loop, context):
        nonlocal exception_handler_called
        exception_handler_called = True

    loop.set_exception_handler(mock.Mock(side_effect=exception_handler))

    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        req = ClientRequest(
            method="GET", url=URL("http://temporary-failure:80"), loop=loop
        )
        conn = aiohttp.TCPConnector(
            use_dns_cache=False,
        )
        m_resolver().resolve.return_value = dns_response_error()
        f = loop.create_task(conn._create_direct_connection(req, [], ClientTimeout(0)))

        await asyncio.sleep(0)
        f.cancel()
        with pytest.raises(asyncio.CancelledError):
            await f

        gc.collect()
        assert exception_handler_called is False


async def test_tcp_connector_dns_tracing(loop: Any, dns_response: Any) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_dns_resolvehost_start = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_dns_resolvehost_end = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_dns_cache_hit = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_dns_cache_miss = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_dns_resolvehost_start.append(on_dns_resolvehost_start)
    trace_config.on_dns_resolvehost_end.append(on_dns_resolvehost_end)
    trace_config.on_dns_cache_hit.append(on_dns_cache_hit)
    trace_config.on_dns_cache_miss.append(on_dns_cache_miss)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)

        m_resolver().resolve.return_value = dns_response()

        await conn._resolve_host("localhost", 8080, traces=traces)
        on_dns_resolvehost_start.assert_called_once_with(
            session,
            trace_config_ctx,
            aiohttp.TraceDnsResolveHostStartParams("localhost"),
        )
        on_dns_resolvehost_end.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsResolveHostEndParams("localhost")
        )
        on_dns_cache_miss.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsCacheMissParams("localhost")
        )
        assert not on_dns_cache_hit.called

        await conn._resolve_host("localhost", 8080, traces=traces)
        on_dns_cache_hit.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsCacheHitParams("localhost")
        )


async def test_tcp_connector_dns_tracing_cache_disabled(
    loop: Any, dns_response: Any
) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_dns_resolvehost_start = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_dns_resolvehost_end = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_dns_resolvehost_start.append(on_dns_resolvehost_start)
    trace_config.on_dns_resolvehost_end.append(on_dns_resolvehost_end)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=False)

        m_resolver().resolve.side_effect = [dns_response(), dns_response()]

        await conn._resolve_host("localhost", 8080, traces=traces)

        await conn._resolve_host("localhost", 8080, traces=traces)

        on_dns_resolvehost_start.assert_has_calls(
            [
                mock.call(
                    session,
                    trace_config_ctx,
                    aiohttp.TraceDnsResolveHostStartParams("localhost"),
                ),
                mock.call(
                    session,
                    trace_config_ctx,
                    aiohttp.TraceDnsResolveHostStartParams("localhost"),
                ),
            ]
        )
        on_dns_resolvehost_end.assert_has_calls(
            [
                mock.call(
                    session,
                    trace_config_ctx,
                    aiohttp.TraceDnsResolveHostEndParams("localhost"),
                ),
                mock.call(
                    session,
                    trace_config_ctx,
                    aiohttp.TraceDnsResolveHostEndParams("localhost"),
                ),
            ]
        )


async def test_tcp_connector_dns_tracing_throttle_requests(
    loop: Any, dns_response: Any
) -> None:

    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_dns_cache_hit = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_dns_cache_miss = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_dns_cache_hit.append(on_dns_cache_hit)
    trace_config.on_dns_cache_miss.append(on_dns_cache_miss)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        loop.create_task(conn._resolve_host("localhost", 8080, traces=traces))
        loop.create_task(conn._resolve_host("localhost", 8080, traces=traces))
        await asyncio.sleep(0)
        on_dns_cache_hit.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsCacheHitParams("localhost")
        )
        on_dns_cache_miss.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsCacheMissParams("localhost")
        )


async def test_dns_error(loop: Any) -> None:
    connector = aiohttp.TCPConnector()
    connector._resolve_host = make_mocked_coro(
        raise_exception=OSError("dont take it serious")
    )

    req = ClientRequest("GET", URL("http://www.python.org"), loop=loop)

    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, [], ClientTimeout())


async def test_get_pop_empty_conns(loop: Any) -> None:
    # see issue #473
    conn = aiohttp.BaseConnector()
    key = ("127.0.0.1", 80, False)
    conn._conns[key] = []
    proto = conn._get(key)
    assert proto is None
    assert not conn._conns


async def test_release_close_do_not_add_to_pool(loop: Any, key: Any) -> None:
    # see issue #473
    conn = aiohttp.BaseConnector()

    proto = create_mocked_conn(loop, should_close=True)

    conn._acquired.add(proto)
    conn._release(key, proto)
    assert not conn._conns


async def test_release_close_do_not_delete_existing_connections(
    loop: Any, key: Any
) -> None:

    proto1 = create_mocked_conn(loop)

    conn = aiohttp.BaseConnector()
    conn._conns[key] = [(proto1, 1)]

    proto = create_mocked_conn(loop, should_close=True)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert conn._conns[key] == [(proto1, 1)]
    assert proto.close.called
    await conn.close()


async def test_release_not_started(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    proto = create_mocked_conn(should_close=False)
    key = 1
    conn._acquired.add(proto)
    conn._release(key, proto)
    # assert conn._conns == {1: [(proto, 10)]}
    rec = conn._conns[1]
    assert rec[0][0] == proto
    assert rec[0][1] == pytest.approx(loop.time(), abs=0.05)
    assert not proto.close.called
    await conn.close()


async def test_release_not_opened(loop: Any, key: Any) -> None:
    conn = aiohttp.BaseConnector()

    proto = create_mocked_conn(loop)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert proto.close.called


async def test_connect(loop: Any, key: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost:80"), loop=loop)

    conn = aiohttp.BaseConnector()
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = create_mocked_conn(loop)
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    connection = await conn.connect(req, [], ClientTimeout())
    assert not conn._create_connection.called
    assert connection._protocol is proto
    assert connection.transport is proto.transport
    assert isinstance(connection, Connection)
    connection.close()


async def test_connect_tracing(loop: Any) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_connection_create_start = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_connection_create_end = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_connection_create_start.append(on_connection_create_start)
    trace_config.on_connection_create_end.append(on_connection_create_end)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector()
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    conn2 = await conn.connect(req, traces, ClientTimeout())
    conn2.release()

    on_connection_create_start.assert_called_with(
        session, trace_config_ctx, aiohttp.TraceConnectionCreateStartParams()
    )
    on_connection_create_end.assert_called_with(
        session, trace_config_ctx, aiohttp.TraceConnectionCreateEndParams()
    )


async def test_close_during_connect(loop: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    fut = loop.create_future()
    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector()
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = fut

    task = loop.create_task(conn.connect(req, None, ClientTimeout()))
    await asyncio.sleep(0)
    await conn.close()

    fut.set_result(proto)
    with pytest.raises(aiohttp.ClientConnectionError):
        await task

    assert proto.close.called


async def test_ctor_cleanup() -> None:
    loop = mock.Mock()
    loop.time.return_value = 1.5
    conn = aiohttp.BaseConnector(keepalive_timeout=10, enable_cleanup_closed=True)
    assert conn._cleanup_handle is None
    assert conn._cleanup_closed_handle is not None


async def test_cleanup(key: Any) -> None:
    testset = {
        key: [(mock.Mock(), 10), (mock.Mock(), 300)],
    }
    testset[key][0][0].is_connected.return_value = True
    testset[key][1][0].is_connected.return_value = False

    loop = mock.Mock()
    loop.time.return_value = 300
    conn = aiohttp.BaseConnector()
    conn._conns = testset
    existing_handle = conn._cleanup_handle = mock.Mock()

    conn._cleanup()
    assert existing_handle.cancel.called
    assert conn._conns == {}
    assert conn._cleanup_handle is None


async def test_cleanup_close_ssl_transport(loop: Any, ssl_key: Any) -> None:
    proto = create_mocked_conn(loop)
    transport = proto.transport
    testset = {ssl_key: [(proto, 10)]}

    loop = mock.Mock()
    loop.time.return_value = asyncio.get_event_loop().time() + 300
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    conn._loop = loop
    conn._conns = testset
    existing_handle = conn._cleanup_handle = mock.Mock()

    conn._cleanup()
    assert existing_handle.cancel.called
    assert conn._conns == {}
    assert conn._cleanup_closed_transports == [transport]


async def test_cleanup2(loop: Any) -> None:
    testset = {1: [(create_mocked_conn(), 300)]}
    testset[1][0][0].is_connected.return_value = True

    conn = aiohttp.BaseConnector(keepalive_timeout=10)
    conn._loop = mock.Mock()
    conn._loop.time.return_value = 300
    conn._conns = testset
    conn._cleanup()
    assert conn._conns == testset

    assert conn._cleanup_handle is not None
    conn._loop.call_at.assert_called_with(310, mock.ANY, mock.ANY)
    await conn.close()


async def test_cleanup3(loop: Any, key: Any) -> None:
    testset = {
        key: [(create_mocked_conn(loop), 290.1), (create_mocked_conn(loop), 305.1)]
    }
    testset[key][0][0].is_connected.return_value = True

    conn = aiohttp.BaseConnector(keepalive_timeout=10)
    conn._loop = mock.Mock()
    conn._loop.time.return_value = 308.5
    conn._conns = testset

    conn._cleanup()
    assert conn._conns == {key: [testset[key][1]]}

    assert conn._cleanup_handle is not None
    conn._loop.call_at.assert_called_with(319, mock.ANY, mock.ANY)
    await conn.close()


async def test_cleanup_closed(loop: Any, mocker: Any) -> None:
    if not hasattr(loop, "__dict__"):
        pytest.skip("can not override loop attributes")

    mocker.spy(loop, "call_at")
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)

    tr = mock.Mock()
    conn._cleanup_closed_handle = cleanup_closed_handle = mock.Mock()
    conn._cleanup_closed_transports = [tr]
    conn._cleanup_closed()
    assert tr.abort.called
    assert not conn._cleanup_closed_transports
    assert loop.call_at.called
    assert cleanup_closed_handle.cancel.called


async def test_cleanup_closed_disabled(loop: Any, mocker: Any) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=False)

    tr = mock.Mock()
    conn._cleanup_closed_transports = [tr]
    conn._cleanup_closed()
    assert tr.abort.called
    assert not conn._cleanup_closed_transports


async def test_tcp_connector_ctor(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    assert conn._ssl is None

    assert conn.use_dns_cache
    assert conn.family == 0


async def test_invalid_ssl_param() -> None:
    with pytest.raises(TypeError):
        aiohttp.TCPConnector(ssl=object())


async def test_tcp_connector_ctor_fingerprint_valid(loop: Any) -> None:
    valid = aiohttp.Fingerprint(hashlib.sha256(b"foo").digest())
    conn = aiohttp.TCPConnector(ssl=valid)
    assert conn._ssl is valid


async def test_insecure_fingerprint_md5(loop: Any) -> None:
    with pytest.raises(ValueError):
        aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(hashlib.md5(b"foo").digest()))


async def test_insecure_fingerprint_sha1(loop: Any) -> None:
    with pytest.raises(ValueError):
        aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(hashlib.sha1(b"foo").digest()))


async def test_tcp_connector_clear_dns_cache(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    hosts = ["a", "b"]
    conn._cached_hosts.add(("localhost", 123), hosts)
    conn._cached_hosts.add(("localhost", 124), hosts)
    conn.clear_dns_cache("localhost", 123)
    with pytest.raises(KeyError):
        conn._cached_hosts.next_addrs(("localhost", 123))

    assert conn._cached_hosts.next_addrs(("localhost", 124)) == hosts

    # Remove removed element is OK
    conn.clear_dns_cache("localhost", 123)
    with pytest.raises(KeyError):
        conn._cached_hosts.next_addrs(("localhost", 123))

    conn.clear_dns_cache()
    with pytest.raises(KeyError):
        conn._cached_hosts.next_addrs(("localhost", 124))


async def test_tcp_connector_clear_dns_cache_bad_args(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    with pytest.raises(ValueError):
        conn.clear_dns_cache("localhost")


async def test_dont_recreate_ssl_context(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    ctx = conn._make_ssl_context(True)
    assert ctx is conn._make_ssl_context(True)


async def test_dont_recreate_ssl_context2(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    ctx = conn._make_ssl_context(False)
    assert ctx is conn._make_ssl_context(False)


async def test___get_ssl_context1(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    req = mock.Mock()
    req.is_ssl.return_value = False
    assert conn._get_ssl_context(req) is None


async def test___get_ssl_context2(loop: Any) -> None:
    ctx = ssl.SSLContext()
    conn = aiohttp.TCPConnector()
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = ctx
    assert conn._get_ssl_context(req) is ctx


async def test___get_ssl_context3(loop: Any) -> None:
    ctx = ssl.SSLContext()
    conn = aiohttp.TCPConnector(ssl=ctx)
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = None
    assert conn._get_ssl_context(req) is ctx


async def test___get_ssl_context4(loop: Any) -> None:
    ctx = ssl.SSLContext()
    conn = aiohttp.TCPConnector(ssl=ctx)
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = False
    assert conn._get_ssl_context(req) is conn._make_ssl_context(False)


async def test___get_ssl_context5(loop: Any) -> None:
    ctx = ssl.SSLContext()
    conn = aiohttp.TCPConnector(ssl=ctx)
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = aiohttp.Fingerprint(hashlib.sha256(b"1").digest())
    assert conn._get_ssl_context(req) is conn._make_ssl_context(False)


async def test___get_ssl_context6(loop: Any) -> None:
    conn = aiohttp.TCPConnector()
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = None
    assert conn._get_ssl_context(req) is conn._make_ssl_context(True)


async def test_close_twice(loop: Any) -> None:
    proto = create_mocked_conn(loop)

    conn = aiohttp.BaseConnector()
    conn._conns[1] = [(proto, object())]
    await conn.close()

    assert not conn._conns
    assert proto.close.called
    assert conn.closed

    conn._conns = "Invalid"  # fill with garbage
    await conn.close()
    assert conn.closed


async def test_close_cancels_cleanup_handle(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    conn._release(1, create_mocked_conn(should_close=False))
    assert conn._cleanup_handle is not None
    await conn.close()
    assert conn._cleanup_handle is None


async def test_close_abort_closed_transports(loop: Any) -> None:
    tr = mock.Mock()

    conn = aiohttp.BaseConnector()
    conn._cleanup_closed_transports.append(tr)
    await conn.close()

    assert not conn._cleanup_closed_transports
    assert tr.abort.called
    assert conn.closed


async def test_close_cancels_cleanup_closed_handle(loop: Any) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    assert conn._cleanup_closed_handle is not None
    await conn.close()
    assert conn._cleanup_closed_handle is None


async def test_ctor_with_default_loop(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    assert loop is conn._loop


async def test_connect_with_limit(loop: Any, key: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )

    conn = aiohttp.BaseConnector(limit=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    connection1 = await conn.connect(req, None, ClientTimeout())
    assert connection1._protocol == proto

    assert 1 == len(conn._acquired)
    assert proto in conn._acquired
    assert key in conn._acquired_per_host
    assert proto in conn._acquired_per_host[key]

    acquired = False

    async def f():
        nonlocal acquired
        connection2 = await conn.connect(req, None, ClientTimeout())
        acquired = True
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        connection2.release()

    task = loop.create_task(f())

    await asyncio.sleep(0.01)
    assert not acquired
    connection1.release()
    await asyncio.sleep(0)
    assert acquired
    await task
    await conn.close()


async def test_connect_queued_operation_tracing(loop: Any, key: Any) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_connection_queued_start = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))
    on_connection_queued_end = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_connection_queued_start.append(on_connection_queued_start)
    trace_config.on_connection_queued_end.append(on_connection_queued_end)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest(
        "GET", URL("http://localhost1:80"), loop=loop, response_class=mock.Mock()
    )

    conn = aiohttp.BaseConnector(limit=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    connection1 = await conn.connect(req, traces, ClientTimeout())

    async def f():
        connection2 = await conn.connect(req, traces, ClientTimeout())
        on_connection_queued_start.assert_called_with(
            session, trace_config_ctx, aiohttp.TraceConnectionQueuedStartParams()
        )
        on_connection_queued_end.assert_called_with(
            session, trace_config_ctx, aiohttp.TraceConnectionQueuedEndParams()
        )
        connection2.release()

    task = asyncio.ensure_future(f())
    await asyncio.sleep(0.01)
    connection1.release()
    await task
    await conn.close()


async def test_connect_reuseconn_tracing(loop: Any, key: Any) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_connection_reuseconn = mock.Mock(side_effect=make_mocked_coro(mock.Mock()))

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_connection_reuseconn.append(on_connection_reuseconn)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )

    conn = aiohttp.BaseConnector(limit=1)
    conn._conns[key] = [(proto, loop.time())]
    conn2 = await conn.connect(req, traces, ClientTimeout())
    conn2.release()

    on_connection_reuseconn.assert_called_with(
        session, trace_config_ctx, aiohttp.TraceConnectionReuseconnParams()
    )
    await conn.close()


async def test_connect_with_limit_and_limit_per_host(loop: Any, key: Any) -> None:

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1000, limit_per_host=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    acquired = False
    connection1 = await conn.connect(req, None, ClientTimeout())

    async def f():
        nonlocal acquired
        connection2 = await conn.connect(req, None, ClientTimeout())
        acquired = True
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        connection2.release()

    task = loop.create_task(f())

    await asyncio.sleep(0.01)
    assert not acquired
    connection1.release()
    await asyncio.sleep(0)
    assert acquired
    await task
    await conn.close()


async def test_connect_with_no_limit_and_limit_per_host(loop: Any, key: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost1:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=0, limit_per_host=1)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    acquired = False
    connection1 = await conn.connect(req, None, ClientTimeout())

    async def f():
        nonlocal acquired
        connection2 = await conn.connect(req, None, ClientTimeout())
        acquired = True
        connection2.release()

    task = loop.create_task(f())

    await asyncio.sleep(0.01)
    assert not acquired
    connection1.release()
    await asyncio.sleep(0)
    assert acquired
    await task
    await conn.close()


async def test_connect_with_no_limits(loop: Any, key: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=0, limit_per_host=0)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    acquired = False
    connection1 = await conn.connect(req, None, ClientTimeout())

    async def f():
        nonlocal acquired
        connection2 = await conn.connect(req, None, ClientTimeout())
        acquired = True
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        connection2.release()

    task = loop.create_task(f())

    await asyncio.sleep(0.01)
    assert acquired
    connection1.release()
    await task
    await conn.close()


async def test_connect_with_limit_cancelled(loop: Any) -> None:

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    key = ("host", 80, False)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    connection = await conn.connect(req, None, ClientTimeout())
    assert connection._protocol == proto
    assert connection.transport == proto.transport

    assert 1 == len(conn._acquired)

    with pytest.raises(asyncio.TimeoutError):
        # limit exhausted
        await asyncio.wait_for(conn.connect(req, None, ClientTimeout()), 0.01)
    connection.close()

    await conn.close()


async def test_connect_with_capacity_release_waiters(loop: Any) -> None:
    def check_with_exc(err):
        conn = aiohttp.BaseConnector(limit=1)
        conn._create_connection = mock.Mock()
        conn._create_connection.return_value = loop.create_future()
        conn._create_connection.return_value.set_exception(err)

        with pytest.raises(Exception):
            req = mock.Mock()
            yield from conn.connect(req, None, ClientTimeout())

        assert not conn._waiters

    check_with_exc(OSError(1, "permission error"))
    check_with_exc(RuntimeError())
    check_with_exc(asyncio.TimeoutError())


async def test_connect_with_limit_concurrent(loop: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.should_close = False
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    max_connections = 2
    num_connections = 0

    conn = aiohttp.BaseConnector(limit=max_connections)

    # Use a real coroutine for _create_connection; a mock would mask
    # problems that only happen when the method yields.

    async def create_connection(req, traces, timeout):
        nonlocal num_connections
        num_connections += 1
        await asyncio.sleep(0)

        # Make a new transport mock each time because acquired
        # transports are stored in a set. Reusing the same object
        # messes with the count.
        proto = create_mocked_conn(loop, should_close=False)
        proto.is_connected.return_value = True

        return proto

    conn._create_connection = create_connection

    # Simulate something like a crawler. It opens a connection, does
    # something with it, closes it, then creates tasks that make more
    # connections and waits for them to finish. The crawler is started
    # with multiple concurrent requests and stops when it hits a
    # predefined maximum number of requests.

    max_requests = 50
    num_requests = 0
    start_requests = max_connections + 1

    async def f(start=True):
        nonlocal num_requests
        if num_requests == max_requests:
            return
        num_requests += 1
        if not start:
            connection = await conn.connect(req, None, ClientTimeout())
            await asyncio.sleep(0)
            connection.release()
            await asyncio.sleep(0)
        tasks = [loop.create_task(f(start=False)) for i in range(start_requests)]
        await asyncio.wait(tasks)

    await f()
    await conn.close()

    assert max_connections == num_connections


async def test_connect_waiters_cleanup(loop: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    conn._available_connections = mock.Mock(return_value=0)

    t = loop.create_task(conn.connect(req, None, ClientTimeout()))

    await asyncio.sleep(0)
    assert conn._waiters.keys()

    t.cancel()
    await asyncio.sleep(0)
    assert not conn._waiters.keys()


async def test_connect_waiters_cleanup_key_error(loop: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    conn._available_connections = mock.Mock(return_value=0)

    t = loop.create_task(conn.connect(req, None, ClientTimeout()))

    await asyncio.sleep(0)
    assert conn._waiters.keys()

    # we delete the entry explicitly before the
    # canceled connection grabs the loop again, we
    # must expect a none failure termination
    conn._waiters.clear()
    t.cancel()
    await asyncio.sleep(0)
    assert not conn._waiters.keys() == []


async def test_close_with_acquired_connection(loop: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    key = ("host", 80, False)
    conn._conns[key] = [(proto, loop.time())]
    conn._create_connection = mock.Mock()
    conn._create_connection.return_value = loop.create_future()
    conn._create_connection.return_value.set_result(proto)

    connection = await conn.connect(req, None, ClientTimeout())

    assert 1 == len(conn._acquired)
    await conn.close()
    assert 0 == len(conn._acquired)
    assert conn.closed
    proto.close.assert_called_with()

    assert not connection.closed
    connection.close()
    assert connection.closed


async def test_default_force_close(loop: Any) -> None:
    connector = aiohttp.BaseConnector()
    assert not connector.force_close


async def test_limit_property(loop: Any) -> None:
    conn = aiohttp.BaseConnector(limit=15)
    assert 15 == conn.limit

    await conn.close()


async def test_limit_per_host_property(loop: Any) -> None:
    conn = aiohttp.BaseConnector(limit_per_host=15)
    assert 15 == conn.limit_per_host

    await conn.close()


async def test_limit_property_default(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    assert conn.limit == 100
    await conn.close()


async def test_limit_per_host_property_default(loop: Any) -> None:
    conn = aiohttp.BaseConnector()
    assert conn.limit_per_host == 0
    await conn.close()


async def test_force_close_and_explicit_keep_alive(loop: Any) -> None:
    with pytest.raises(ValueError):
        aiohttp.BaseConnector(keepalive_timeout=30, force_close=True)

    conn = aiohttp.BaseConnector(force_close=True, keepalive_timeout=None)
    assert conn

    conn = aiohttp.BaseConnector(force_close=True)

    assert conn


async def test_error_on_connection(loop: Any, key: Any) -> None:
    conn = aiohttp.BaseConnector(limit=1)

    req = mock.Mock()
    req.connection_key = key
    proto = create_mocked_conn(loop)
    i = 0

    fut = loop.create_future()
    exc = OSError()

    async def create_connection(req, traces, timeout):
        nonlocal i
        i += 1
        if i == 1:
            await fut
            raise exc
        elif i == 2:
            return proto

    conn._create_connection = create_connection

    t1 = loop.create_task(conn.connect(req, None, ClientTimeout()))
    t2 = loop.create_task(conn.connect(req, None, ClientTimeout()))
    await asyncio.sleep(0)
    assert not t1.done()
    assert not t2.done()
    assert len(conn._acquired_per_host[key]) == 1

    fut.set_result(None)
    with pytest.raises(OSError):
        await t1

    ret = await t2
    assert len(conn._acquired_per_host[key]) == 1

    assert ret._key == key
    assert ret.protocol == proto
    assert proto in conn._acquired
    ret.release()


async def test_cancelled_waiter(loop: Any) -> None:
    conn = aiohttp.BaseConnector(limit=1)
    req = mock.Mock()
    req.connection_key = "key"
    proto = create_mocked_conn(loop)

    async def create_connection(req, traces=None):
        await asyncio.sleep(1)
        return proto

    conn._create_connection = create_connection

    conn._acquired.add(proto)

    conn2 = loop.create_task(conn.connect(req, None, ClientTimeout()))
    await asyncio.sleep(0)
    conn2.cancel()

    with pytest.raises(asyncio.CancelledError):
        await conn2


async def test_error_on_connection_with_cancelled_waiter(loop: Any, key: Any) -> None:

    conn = aiohttp.BaseConnector(limit=1)

    req = mock.Mock()
    req.connection_key = key
    proto = create_mocked_conn()
    i = 0

    fut1 = loop.create_future()
    fut2 = loop.create_future()
    exc = OSError()

    async def create_connection(req, traces, timeout):
        nonlocal i
        i += 1
        if i == 1:
            await fut1
            raise exc
        if i == 2:
            await fut2
        elif i == 3:
            return proto

    conn._create_connection = create_connection

    t1 = loop.create_task(conn.connect(req, None, ClientTimeout()))
    t2 = loop.create_task(conn.connect(req, None, ClientTimeout()))
    t3 = loop.create_task(conn.connect(req, None, ClientTimeout()))
    await asyncio.sleep(0)
    assert not t1.done()
    assert not t2.done()
    assert len(conn._acquired_per_host[key]) == 1

    fut1.set_result(None)
    fut2.cancel()
    with pytest.raises(OSError):
        await t1

    with pytest.raises(asyncio.CancelledError):
        await t2

    ret = await t3
    assert len(conn._acquired_per_host[key]) == 1

    assert ret._key == key
    assert ret.protocol == proto
    assert proto in conn._acquired
    ret.release()


async def test_tcp_connector(aiohttp_client: Any, loop: Any) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    r = await client.get("/")
    assert r.status == 200


@needs_unix
async def test_unix_connector_not_found(loop: Any) -> None:
    connector = aiohttp.UnixConnector("/" + uuid.uuid4().hex)

    req = ClientRequest("GET", URL("http://www.python.org"), loop=loop)
    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, None, ClientTimeout())


@needs_unix
async def test_unix_connector_permission(loop: Any) -> None:
    loop.create_unix_connection = make_mocked_coro(raise_exception=PermissionError())
    connector = aiohttp.UnixConnector("/" + uuid.uuid4().hex)

    req = ClientRequest("GET", URL("http://www.python.org"), loop=loop)
    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, None, ClientTimeout())


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector_wrong_loop(
    selector_loop: Any, pipe_name: Any
) -> None:
    with pytest.raises(RuntimeError):
        aiohttp.NamedPipeConnector(pipe_name)


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector_not_found(
    proactor_loop: Any, pipe_name: Any
) -> None:
    asyncio.set_event_loop(proactor_loop)
    connector = aiohttp.NamedPipeConnector(pipe_name)

    req = ClientRequest("GET", URL("http://www.python.org"), loop=proactor_loop)
    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, None, ClientTimeout())


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector_permission(
    proactor_loop: Any, pipe_name: Any
) -> None:
    proactor_loop.create_pipe_connection = make_mocked_coro(
        raise_exception=PermissionError()
    )
    asyncio.set_event_loop(proactor_loop)
    connector = aiohttp.NamedPipeConnector(pipe_name)

    req = ClientRequest("GET", URL("http://www.python.org"), loop=proactor_loop)
    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, None, ClientTimeout())


async def test_default_use_dns_cache() -> None:
    conn = aiohttp.TCPConnector()
    assert conn.use_dns_cache


async def test_resolver_not_called_with_address_is_ip(loop: Any) -> None:
    resolver = mock.MagicMock()
    connector = aiohttp.TCPConnector(resolver=resolver)

    req = ClientRequest(
        "GET",
        URL(f"http://127.0.0.1:{unused_port()}"),
        loop=loop,
        response_class=mock.Mock(),
    )

    with pytest.raises(OSError):
        await connector.connect(req, None, ClientTimeout())

    resolver.resolve.assert_not_called()


async def test_tcp_connector_raise_connector_ssl_error(
    aiohttp_server: Any, ssl_ctx: Any
) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    srv = await aiohttp_server(app, ssl=ssl_ctx)

    port = unused_port()
    conn = aiohttp.TCPConnector(local_addr=("127.0.0.1", port))

    session = aiohttp.ClientSession(connector=conn)
    url = srv.make_url("/")

    err = aiohttp.ClientConnectorCertificateError
    with pytest.raises(err) as ctx:
        await session.get(url)

    assert isinstance(ctx.value, aiohttp.ClientConnectorCertificateError)
    assert isinstance(ctx.value.certificate_error, ssl.SSLError)

    await session.close()


async def test_tcp_connector_do_not_raise_connector_ssl_error(
    aiohttp_server: Any, ssl_ctx: Any, client_ssl_ctx: Any
) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    srv = await aiohttp_server(app, ssl=ssl_ctx)
    port = unused_port()
    conn = aiohttp.TCPConnector(local_addr=("127.0.0.1", port))

    session = aiohttp.ClientSession(connector=conn)
    url = srv.make_url("/")

    r = await session.get(url, ssl=client_ssl_ctx)

    r.release()
    first_conn = next(iter(conn._conns.values()))[0][0]

    try:
        _sslcontext = first_conn.transport._ssl_protocol._sslcontext
    except AttributeError:
        _sslcontext = first_conn.transport._sslcontext

    assert _sslcontext is client_ssl_ctx
    r.close()

    await session.close()
    await conn.close()


async def test_tcp_connector_uses_provided_local_addr(aiohttp_server: Any) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    srv = await aiohttp_server(app)

    port = unused_port()
    conn = aiohttp.TCPConnector(local_addr=("127.0.0.1", port))

    session = aiohttp.ClientSession(connector=conn)
    url = srv.make_url("/")

    r = await session.get(url)
    r.release()

    first_conn = next(iter(conn._conns.values()))[0][0]
    assert first_conn.transport.get_extra_info("sockname") == ("127.0.0.1", port)
    r.close()
    await session.close()
    await conn.close()


async def test_unix_connector(unix_server: Any, unix_sockname: Any) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    await unix_server(app)

    url = "http://127.0.0.1/"

    connector = aiohttp.UnixConnector(unix_sockname)
    assert unix_sockname == connector.path

    session = client.ClientSession(connector=connector)
    r = await session.get(url)
    assert r.status == 200
    r.close()
    await session.close()


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector(
    proactor_loop: Any, named_pipe_server: Any, pipe_name: Any
) -> None:
    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    await named_pipe_server(app)

    url = "http://this-does-not-matter.com"

    connector = aiohttp.NamedPipeConnector(pipe_name)
    assert pipe_name == connector.path

    session = client.ClientSession(connector=connector)
    r = await session.get(url)
    assert r.status == 200
    r.close()
    await session.close()


class TestDNSCacheTable:
    @pytest.fixture
    def dns_cache_table(self):
        return _DNSCacheTable()

    def test_next_addrs_basic(self, dns_cache_table: Any) -> None:
        dns_cache_table.add("localhost", ["127.0.0.1"])
        dns_cache_table.add("foo", ["127.0.0.2"])

        addrs = dns_cache_table.next_addrs("localhost")
        assert addrs == ["127.0.0.1"]
        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.2"]
        with pytest.raises(KeyError):
            dns_cache_table.next_addrs("no-such-host")

    def test_remove(self, dns_cache_table: Any) -> None:
        dns_cache_table.add("localhost", ["127.0.0.1"])
        dns_cache_table.remove("localhost")
        with pytest.raises(KeyError):
            dns_cache_table.next_addrs("localhost")

    def test_clear(self, dns_cache_table: Any) -> None:
        dns_cache_table.add("localhost", ["127.0.0.1"])
        dns_cache_table.clear()
        with pytest.raises(KeyError):
            dns_cache_table.next_addrs("localhost")

    def test_not_expired_ttl_None(self, dns_cache_table: Any) -> None:
        dns_cache_table.add("localhost", ["127.0.0.1"])
        assert not dns_cache_table.expired("localhost")

    def test_not_expired_ttl(self) -> None:
        dns_cache_table = _DNSCacheTable(ttl=0.1)
        dns_cache_table.add("localhost", ["127.0.0.1"])
        assert not dns_cache_table.expired("localhost")

    async def test_expired_ttl(self, loop: Any) -> None:
        dns_cache_table = _DNSCacheTable(ttl=0.01)
        dns_cache_table.add("localhost", ["127.0.0.1"])
        await asyncio.sleep(0.02)
        assert dns_cache_table.expired("localhost")

    def test_next_addrs(self, dns_cache_table: Any) -> None:
        dns_cache_table.add("foo", ["127.0.0.1", "127.0.0.2", "127.0.0.3"])

        # Each calls to next_addrs return the hosts using
        # a round robin strategy.
        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]

        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.2", "127.0.0.3", "127.0.0.1"]

        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.3", "127.0.0.1", "127.0.0.2"]

        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]

    def test_next_addrs_single(self, dns_cache_table: Any) -> None:
        dns_cache_table.add("foo", ["127.0.0.1"])

        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.1"]

        addrs = dns_cache_table.next_addrs("foo")
        assert addrs == ["127.0.0.1"]


async def test_connector_cache_trace_race() -> None:
    class DummyTracer:
        async def send_dns_cache_hit(self, *args, **kwargs):
            connector._cached_hosts.remove(("", 0))

    token = object()
    connector = TCPConnector()
    connector._cached_hosts.add(("", 0), [token])

    traces = [DummyTracer()]
    assert await connector._resolve_host("", 0, traces) == [token]


async def test_connector_throttle_trace_race(loop: Any) -> None:
    key = ("", 0)
    token = object()

    class DummyTracer:
        async def send_dns_cache_hit(self, *args, **kwargs):
            event = connector._throttle_dns_events.pop(key)
            event.set()
            connector._cached_hosts.add(key, [token])

    connector = TCPConnector()
    connector._throttle_dns_events[key] = EventResultOrError(loop)
    traces = [DummyTracer()]
    assert await connector._resolve_host("", 0, traces) == [token]


async def test_connector_does_not_remove_needed_waiters(loop: Any, key: Any) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("https://localhost:80"), loop=loop)
    connection_key = req.connection_key

    connector = aiohttp.BaseConnector()
    connector._available_connections = mock.Mock(return_value=0)
    connector._conns[key] = [(proto, loop.time())]
    connector._create_connection = create_mocked_conn(loop)
    connector._create_connection.return_value = loop.create_future()
    connector._create_connection.return_value.set_result(proto)

    dummy_waiter = loop.create_future()

    async def await_connection_and_check_waiters() -> None:
        connection = await connector.connect(req, [], ClientTimeout())
        try:
            assert connection_key in connector._waiters
            assert dummy_waiter in connector._waiters[connection_key]
        finally:
            connection.close()

    async def allow_connection_and_add_dummy_waiter() -> None:
        # `asyncio.gather` may execute coroutines not in order.
        # Skip one event loop run cycle in such a case.
        if connection_key not in connector._waiters:
            await asyncio.sleep(0)
        connector._waiters[connection_key].popleft().set_result(None)
        del connector._waiters[connection_key]
        connector._waiters[connection_key].append(dummy_waiter)

    await asyncio.gather(
        await_connection_and_check_waiters(),
        allow_connection_and_add_dummy_waiter(),
    )

    await connector.close()
