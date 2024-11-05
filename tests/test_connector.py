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
from concurrent import futures
from contextlib import closing, suppress
from typing import (
    Awaitable,
    Callable,
    Deque,
    Dict,
    Iterator,
    List,
    Literal,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
)
from unittest import mock

import pytest
from aiohappyeyeballs import AddrInfoType
from pytest_mock import MockerFixture
from yarl import URL

import aiohttp
from aiohttp import (
    ClientRequest,
    ClientSession,
    ClientTimeout,
    connector as connector_module,
    web,
)
from aiohttp.abc import ResolveResult
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ConnectionKey
from aiohttp.connector import (
    _SSL_CONTEXT_UNVERIFIED,
    _SSL_CONTEXT_VERIFIED,
    Connection,
    TCPConnector,
    _DNSCacheTable,
)
from aiohttp.pytest_plugin import AiohttpClient, AiohttpServer
from aiohttp.test_utils import make_mocked_coro, unused_port
from aiohttp.tracing import Trace


@pytest.fixture()
def key() -> ConnectionKey:
    # Connection key
    return ConnectionKey("localhost", 80, False, True, None, None, None)


@pytest.fixture
def key2() -> ConnectionKey:
    # Connection key
    return ConnectionKey("localhost", 80, False, True, None, None, None)


@pytest.fixture
def other_host_key2() -> ConnectionKey:
    # Connection key
    return ConnectionKey("otherhost", 80, False, True, None, None, None)


@pytest.fixture
def ssl_key() -> ConnectionKey:
    # Connection key
    return ConnectionKey("localhost", 80, True, True, None, None, None)


@pytest.fixture
def unix_server(
    loop: asyncio.AbstractEventLoop, unix_sockname: str
) -> Iterator[Callable[[web.Application], Awaitable[None]]]:
    runners = []

    async def go(app: web.Application) -> None:
        runner = web.AppRunner(app)
        runners.append(runner)
        await runner.setup()
        site = web.UnixSite(runner, unix_sockname)
        await site.start()

    yield go

    for runner in runners:
        loop.run_until_complete(runner.cleanup())


@pytest.fixture
def named_pipe_server(
    proactor_loop: asyncio.AbstractEventLoop, pipe_name: str
) -> Iterator[Callable[[web.Application], Awaitable[None]]]:
    runners = []

    async def go(app: web.Application) -> None:
        runner = web.AppRunner(app)
        runners.append(runner)
        await runner.setup()
        site = web.NamedPipeSite(runner, pipe_name)
        await site.start()

    yield go

    for runner in runners:
        proactor_loop.run_until_complete(runner.cleanup())


def create_mocked_conn(
    conn_closing_result: Optional[asyncio.AbstractEventLoop] = None,
    should_close: bool = True,
    **kwargs: object,
) -> mock.Mock:
    assert "loop" not in kwargs
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.get_event_loop_policy().get_event_loop()

    f = loop.create_future()
    proto: mock.Mock = mock.create_autospec(
        ResponseHandler, instance=True, should_close=should_close, closed=f
    )
    f.set_result(conn_closing_result)
    return proto


async def test_connection_del(loop: asyncio.AbstractEventLoop) -> None:
    connector = mock.Mock()
    key = mock.Mock()
    protocol = mock.Mock()
    loop.set_debug(False)
    conn = Connection(connector, key, protocol, loop=loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    await asyncio.sleep(0)
    connector._release.assert_called_with(key, protocol, should_close=True)
    msg = {
        "message": mock.ANY,
        "client_connection": mock.ANY,
    }
    exc_handler.assert_called_with(loop, msg)


def test_connection_del_loop_debug(loop: asyncio.AbstractEventLoop) -> None:
    connector = mock.Mock()
    key = mock.Mock()
    protocol = mock.Mock()
    loop.set_debug(True)
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


def test_connection_del_loop_closed(loop: asyncio.AbstractEventLoop) -> None:
    connector = mock.Mock()
    key = mock.Mock()
    protocol = mock.Mock()
    loop.set_debug(True)
    conn = Connection(connector, key, protocol, loop=loop)
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)
    loop.close()

    with pytest.warns(ResourceWarning):
        del conn
        gc.collect()

    assert not connector._release.called
    assert not exc_handler.called


async def test_del(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    conn = aiohttp.BaseConnector()
    proto = create_mocked_conn(loop, should_close=False)
    conn._release(key, proto)
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
async def test_del_with_scheduled_cleanup(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    loop.set_debug(True)
    conn = aiohttp.BaseConnector(keepalive_timeout=0.01)
    transp = create_mocked_conn(loop)
    conn._conns[key] = deque([(transp, 123)])

    conns_impl = conn._conns
    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    with pytest.warns(ResourceWarning):
        # obviously doesn't deletion because loop has a strong
        # reference to connector's instance method, isn't it?
        del conn
        await asyncio.sleep(0.01)
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
def test_del_with_closed_loop(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    async def make_conn() -> aiohttp.BaseConnector:
        return aiohttp.BaseConnector()

    conn = loop.run_until_complete(make_conn())
    transp = create_mocked_conn(loop)
    conn._conns[key] = deque([(transp, 123)])

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


async def test_del_empty_connector(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()

    exc_handler = mock.Mock()
    loop.set_exception_handler(exc_handler)

    del conn

    assert not exc_handler.called


async def test_create_conn() -> None:
    conn = aiohttp.BaseConnector()
    with pytest.raises(NotImplementedError):
        await conn._create_connection(object(), [], object())  # type: ignore[arg-type]


async def test_async_context_manager(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()

    async with conn as c:
        assert conn is c

    assert conn.closed


async def test_close(key: ConnectionKey) -> None:
    proto = create_mocked_conn()

    conn = aiohttp.BaseConnector()
    assert not conn.closed
    conn._conns[key] = deque([(proto, 0)])
    await conn.close()

    assert not conn._conns
    assert proto.close.called
    assert conn.closed


async def test_get(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    conn = aiohttp.BaseConnector()
    assert await conn._get(key, []) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = deque([(proto, loop.time())])
    connection = await conn._get(key, [])
    assert connection is not None
    assert connection.protocol == proto
    connection.close()
    await conn.close()


async def test_get_unconnected_proto(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()
    key = ConnectionKey("localhost", 80, False, False, None, None, None)
    assert await conn._get(key, []) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = deque([(proto, loop.time())])
    connection = await conn._get(key, [])
    assert connection is not None
    assert connection.protocol == proto
    connection.close()

    assert await conn._get(key, []) is None
    conn._conns[key] = deque([(proto, loop.time())])
    proto.is_connected = lambda *args: False
    assert await conn._get(key, []) is None
    await conn.close()


async def test_get_unconnected_proto_ssl(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()
    key = ConnectionKey("localhost", 80, True, False, None, None, None)
    assert await conn._get(key, []) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = deque([(proto, loop.time())])
    connection = await conn._get(key, [])
    assert connection is not None
    assert connection.protocol == proto
    connection.close()

    assert await conn._get(key, []) is None
    conn._conns[key] = deque([(proto, loop.time())])
    proto.is_connected = lambda *args: False
    assert await conn._get(key, []) is None
    await conn.close()


async def test_get_expired(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()
    key = ConnectionKey("localhost", 80, False, False, None, None, None)
    assert await conn._get(key, []) is None

    proto = create_mocked_conn(loop)
    conn._conns[key] = deque([(proto, loop.time() - 1000)])
    assert await conn._get(key, []) is None
    assert not conn._conns
    await conn.close()


async def test_get_expired_ssl(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    key = ConnectionKey("localhost", 80, True, False, None, None, None)
    assert await conn._get(key, []) is None

    proto = create_mocked_conn(loop)
    transport = proto.transport
    conn._conns[key] = deque([(proto, loop.time() - 1000)])
    assert await conn._get(key, []) is None
    assert not conn._conns
    assert conn._cleanup_closed_transports == [transport]
    await conn.close()


async def test_release_acquired(key: ConnectionKey) -> None:
    proto = create_mocked_conn()
    conn = aiohttp.BaseConnector(limit=5)
    with mock.patch.object(conn, "_release_waiter", autospec=True, spec_set=True) as m:
        conn._acquired.add(proto)
        conn._acquired_per_host[key].add(proto)
        conn._release_acquired(key, proto)
        assert 0 == len(conn._acquired)
        assert 0 == len(conn._acquired_per_host)
        assert m.called

        conn._release_acquired(key, proto)
        assert 0 == len(conn._acquired)
        assert 0 == len(conn._acquired_per_host)

        await conn.close()


async def test_release_acquired_closed(key: ConnectionKey) -> None:
    proto = create_mocked_conn()
    conn = aiohttp.BaseConnector(limit=5)
    with mock.patch.object(conn, "_release_waiter", autospec=True, spec_set=True) as m:
        conn._acquired.add(proto)
        conn._acquired_per_host[key].add(proto)
        conn._closed = True
        conn._release_acquired(key, proto)
        assert 1 == len(conn._acquired)
        assert 1 == len(conn._acquired_per_host[key])
        assert not m.called
        await conn.close()


async def test_release(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    conn = aiohttp.BaseConnector()
    with mock.patch.object(conn, "_release_waiter", autospec=True, spec_set=True) as m:
        proto = create_mocked_conn(loop, should_close=False)

        conn._acquired.add(proto)
        conn._acquired_per_host[key].add(proto)

        conn._release(key, proto)
        assert m.called
        assert conn._cleanup_handle is not None
        assert conn._conns[key][0][0] == proto
        assert conn._conns[key][0][1] == pytest.approx(loop.time(), abs=0.1)
        assert not conn._cleanup_closed_transports
        await conn.close()


async def test_release_ssl_transport(
    loop: asyncio.AbstractEventLoop, ssl_key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    with mock.patch.object(conn, "_release_waiter", autospec=True, spec_set=True):
        proto = create_mocked_conn(loop)
        transport = proto.transport
        conn._acquired.add(proto)
        conn._acquired_per_host[ssl_key].add(proto)

        conn._release(ssl_key, proto, should_close=True)
        assert conn._cleanup_closed_transports == [transport]
        await conn.close()


async def test_release_already_closed(key: ConnectionKey) -> None:
    conn = aiohttp.BaseConnector()

    proto = create_mocked_conn()
    conn._acquired.add(proto)
    await conn.close()

    with mock.patch.object(
        conn, "_release_acquired", autospec=True, spec_set=True
    ) as m1:
        with mock.patch.object(
            conn, "_release_waiter", autospec=True, spec_set=True
        ) as m2:
            conn._release(key, proto)
            assert not m1.called
            assert not m2.called


async def test_release_waiter_no_limit(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey, key2: ConnectionKey
) -> None:
    # limit is 0
    conn = aiohttp.BaseConnector(limit=0)
    w = mock.Mock()
    w.done.return_value = False
    conn._waiters[key][w] = None
    conn._release_waiter()
    assert len(conn._waiters[key]) == 0
    assert w.done.called
    await conn.close()


async def test_release_waiter_first_available(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey, key2: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key][w2] = None
    conn._waiters[key2][w1] = None
    conn._release_waiter()
    assert (
        w1.set_result.called
        and not w2.set_result.called
        or not w1.set_result.called
        and w2.set_result.called
    )
    await conn.close()


async def test_release_waiter_release_first(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey, key2: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector(limit=1)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key][w1] = None
    conn._waiters[key][w2] = None
    conn._release_waiter()
    assert w1.set_result.called
    assert not w2.set_result.called
    await conn.close()


async def test_release_waiter_skip_done_waiter(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey, key2: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector(limit=1)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = True
    w2.done.return_value = False
    conn._waiters[key][w1] = None
    conn._waiters[key][w2] = None
    conn._release_waiter()
    assert not w1.set_result.called
    assert w2.set_result.called
    await conn.close()


async def test_release_waiter_per_host(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey, key2: ConnectionKey
) -> None:
    # no limit
    conn = aiohttp.BaseConnector(limit=0, limit_per_host=2)
    w1, w2 = mock.Mock(), mock.Mock()
    w1.done.return_value = False
    w2.done.return_value = False
    conn._waiters[key][w1] = None
    conn._waiters[key2][w2] = None
    conn._release_waiter()
    assert (w1.set_result.called and not w2.set_result.called) or (
        not w1.set_result.called and w2.set_result.called
    )
    await conn.close()


async def test_release_waiter_no_available(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey, key2: ConnectionKey
) -> None:
    # limit is 0
    conn = aiohttp.BaseConnector(limit=0)
    w = mock.Mock()
    w.done.return_value = False
    conn._waiters[key][w] = None
    with mock.patch.object(
        conn, "_available_connections", autospec=True, spec_set=True, return_value=0
    ):
        conn._release_waiter()
        assert len(conn._waiters) == 1
        assert not w.done.called
        await conn.close()


async def test_release_close(key: ConnectionKey) -> None:
    conn = aiohttp.BaseConnector()
    proto = create_mocked_conn(should_close=True)

    conn._acquired.add(proto)
    conn._release(key, proto)
    assert not conn._conns
    assert proto.close.called


async def test_release_proto_closed_future(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    protocol = mock.Mock(should_close=True, closed=loop.create_future())
    conn._release(key, protocol)
    # See PR #6321
    assert protocol.closed.result() is None


async def test__release_acquired_per_host1(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    conn._release_acquired(key, create_mocked_conn(loop))
    assert len(conn._acquired_per_host) == 0


async def test__release_acquired_per_host2(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    handler = create_mocked_conn(loop)
    conn._acquired_per_host[key].add(handler)
    conn._release_acquired(key, handler)
    assert len(conn._acquired_per_host) == 0


async def test__release_acquired_per_host3(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    handler = create_mocked_conn(loop)
    handler2 = create_mocked_conn(loop)
    conn._acquired_per_host[key].add(handler)
    conn._acquired_per_host[key].add(handler2)
    conn._release_acquired(key, handler)
    assert len(conn._acquired_per_host) == 1
    assert conn._acquired_per_host[key] == {handler2}


async def test_tcp_connector_certificate_error(
    loop: asyncio.AbstractEventLoop, start_connection: mock.AsyncMock
) -> None:
    req = ClientRequest("GET", URL("https://127.0.0.1:443"), loop=loop)

    conn = aiohttp.TCPConnector()
    with mock.patch.object(
        conn._loop,
        "create_connection",
        autospec=True,
        spec_set=True,
        side_effect=ssl.CertificateError,
    ):
        with pytest.raises(aiohttp.ClientConnectorCertificateError) as ctx:
            await conn.connect(req, [], ClientTimeout())

        assert isinstance(ctx.value, ssl.CertificateError)
        assert isinstance(ctx.value.certificate_error, ssl.CertificateError)
        assert isinstance(ctx.value, aiohttp.ClientSSLError)


async def test_tcp_connector_server_hostname_default(
    loop: asyncio.AbstractEventLoop, start_connection: mock.AsyncMock
) -> None:
    conn = aiohttp.TCPConnector()

    with mock.patch.object(
        conn._loop, "create_connection", autospec=True, spec_set=True
    ) as create_connection:
        create_connection.return_value = mock.Mock(), mock.Mock()

        req = ClientRequest("GET", URL("https://127.0.0.1:443"), loop=loop)

        with closing(await conn.connect(req, [], ClientTimeout())):
            assert create_connection.call_args.kwargs["server_hostname"] == "127.0.0.1"


async def test_tcp_connector_server_hostname_override(
    loop: asyncio.AbstractEventLoop, start_connection: mock.AsyncMock
) -> None:
    conn = aiohttp.TCPConnector()

    with mock.patch.object(
        conn._loop, "create_connection", autospec=True, spec_set=True
    ) as create_connection:
        create_connection.return_value = mock.Mock(), mock.Mock()

        req = ClientRequest(
            "GET", URL("https://127.0.0.1:443"), loop=loop, server_hostname="localhost"
        )

        with closing(await conn.connect(req, [], ClientTimeout())):
            assert create_connection.call_args.kwargs["server_hostname"] == "localhost"


async def test_tcp_connector_multiple_hosts_errors(
    loop: asyncio.AbstractEventLoop,
) -> None:
    conn = aiohttp.TCPConnector()

    ip1 = "192.168.1.1"
    ip2 = "192.168.1.2"
    ip3 = "192.168.1.3"
    ip4 = "192.168.1.4"
    ip5 = "192.168.1.5"
    ips = [ip1, ip2, ip3, ip4, ip5]
    addrs_tried = []
    ips_tried = []

    fingerprint = hashlib.sha256(b"foo").digest()

    req = ClientRequest(
        "GET",
        URL("https://mocked.host"),
        ssl=aiohttp.Fingerprint(fingerprint),
        loop=loop,
    )

    async def _resolve_host(
        host: str, port: int, traces: object = None
    ) -> List[ResolveResult]:
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

    os_error = certificate_error = ssl_error = fingerprint_error = False
    connected = False

    async def start_connection(
        addr_infos: Sequence[AddrInfoType], **kwargs: object
    ) -> socket.socket:
        first_addr_info = addr_infos[0]
        first_addr_info_addr = first_addr_info[-1]
        addrs_tried.append(first_addr_info_addr)

        mock_socket = mock.create_autospec(socket.socket, spec_set=True, instance=True)
        mock_socket.getpeername.return_value = first_addr_info_addr
        return mock_socket  # type: ignore[no-any-return]

    async def create_connection(
        *args: object, sock: Optional[socket.socket] = None, **kwargs: object
    ) -> Tuple[ResponseHandler, ResponseHandler]:
        nonlocal os_error, certificate_error, ssl_error, fingerprint_error
        nonlocal connected

        assert isinstance(sock, socket.socket)
        addr_info = sock.getpeername()
        ip = addr_info[0]

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
            # Close the socket since we are not actually connecting
            # and we don't want to leak it.
            sock.close()

            fingerprint_error = True
            tr = create_mocked_conn(loop)
            pr = create_mocked_conn(loop)

            def get_extra_info(param: str) -> object:
                if param == "sslcontext":
                    return True

                if param == "ssl_object":
                    s = mock.Mock()
                    s.getpeercert.return_value = b"not foo"
                    return s

                if param == "peername":
                    return ("192.168.1.5", 12345)

                if param == "socket":
                    return sock

                assert False, param

            tr.get_extra_info = get_extra_info
            return tr, pr

        if ip == ip5:
            # Close the socket since we are not actually connecting
            # and we don't want to leak it.
            sock.close()

            connected = True
            tr = create_mocked_conn(loop)
            pr = create_mocked_conn(loop)

            def get_extra_info(param: str) -> object:
                if param == "sslcontext":
                    return True

                if param == "ssl_object":
                    s = mock.Mock()
                    s.getpeercert.return_value = b"foo"
                    return s

                assert False

            tr.get_extra_info = get_extra_info
            return tr, pr

        assert False

    with mock.patch.object(
        conn, "_resolve_host", autospec=True, spec_set=True, side_effect=_resolve_host
    ), mock.patch.object(
        conn._loop,
        "create_connection",
        autospec=True,
        spec_set=True,
        side_effect=create_connection,
    ), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection", start_connection
    ):
        established_connection = await conn.connect(req, [], ClientTimeout())

    assert ips_tried == ips
    assert addrs_tried == [(ip, 443) for ip in ips]

    assert os_error
    assert certificate_error
    assert ssl_error
    assert fingerprint_error
    assert connected

    established_connection.close()


@pytest.mark.parametrize(
    ("happy_eyeballs_delay"),
    [0.1, 0.25, None],
)
async def test_tcp_connector_happy_eyeballs(
    loop: asyncio.AbstractEventLoop, happy_eyeballs_delay: Optional[float]
) -> None:
    conn = aiohttp.TCPConnector(happy_eyeballs_delay=happy_eyeballs_delay)

    ip1 = "dead::beef::"
    ip2 = "192.168.1.1"
    ips = [ip1, ip2]
    addrs_tried = []

    req = ClientRequest(
        "GET",
        URL("https://mocked.host"),
        loop=loop,
    )

    async def _resolve_host(
        host: str, port: int, traces: object = None
    ) -> List[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in ips
        ]

    os_error = False
    connected = False

    async def sock_connect(*args: Tuple[str, int], **kwargs: object) -> None:
        addr = args[1]
        nonlocal os_error

        addrs_tried.append(addr)

        if addr[0] == ip1:
            os_error = True
            raise OSError

    async def create_connection(
        *args: object, sock: Optional[socket.socket] = None, **kwargs: object
    ) -> Tuple[ResponseHandler, ResponseHandler]:
        assert isinstance(sock, socket.socket)
        # Close the socket since we are not actually connecting
        # and we don't want to leak it.
        sock.close()

        nonlocal connected
        connected = True
        tr = create_mocked_conn(loop)
        pr = create_mocked_conn(loop)
        return tr, pr

    with mock.patch.object(
        conn, "_resolve_host", autospec=True, spec_set=True, side_effect=_resolve_host
    ):
        with mock.patch.object(
            conn._loop,
            "sock_connect",
            autospec=True,
            spec_set=True,
            side_effect=sock_connect,
        ):
            with mock.patch.object(
                conn._loop,
                "create_connection",
                autospec=True,
                spec_set=True,
                side_effect=create_connection,
            ):
                established_connection = await conn.connect(req, [], ClientTimeout())

                assert addrs_tried == [(ip1, 443, 0, 0), (ip2, 443)]

                assert os_error
                assert connected

                established_connection.close()


async def test_tcp_connector_interleave(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.TCPConnector(interleave=2)

    ip1 = "192.168.1.1"
    ip2 = "192.168.1.2"
    ip3 = "dead::beef::"
    ip4 = "aaaa::beef::"
    ip5 = "192.168.1.5"
    ips = [ip1, ip2, ip3, ip4, ip5]
    success_ips = []
    interleave_val = None

    req = ClientRequest(
        "GET",
        URL("https://mocked.host"),
        loop=loop,
    )

    async def _resolve_host(
        host: str, port: int, traces: object = None
    ) -> List[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in ips
        ]

    async def start_connection(
        addr_infos: Sequence[AddrInfoType],
        *,
        interleave: Optional[int] = None,
        **kwargs: object,
    ) -> socket.socket:
        nonlocal interleave_val
        interleave_val = interleave
        # Mock the 4th host connecting successfully
        fourth_addr_info = addr_infos[3]
        fourth_addr_info_addr = fourth_addr_info[-1]
        mock_socket = mock.create_autospec(socket.socket, spec_set=True, instance=True)
        mock_socket.getpeername.return_value = fourth_addr_info_addr
        return mock_socket  # type: ignore[no-any-return]

    async def create_connection(
        *args: object, sock: Optional[socket.socket] = None, **kwargs: object
    ) -> Tuple[ResponseHandler, ResponseHandler]:
        assert isinstance(sock, socket.socket)
        addr_info = sock.getpeername()
        ip = addr_info[0]

        success_ips.append(ip)

        # Close the socket since we are not actually connecting
        # and we don't want to leak it.
        sock.close()
        tr = create_mocked_conn(loop)
        pr = create_mocked_conn(loop)
        return tr, pr

    with mock.patch.object(
        conn, "_resolve_host", autospec=True, spec_set=True, side_effect=_resolve_host
    ), mock.patch.object(
        conn._loop,
        "create_connection",
        autospec=True,
        spec_set=True,
        side_effect=create_connection,
    ), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection", start_connection
    ):
        established_connection = await conn.connect(req, [], ClientTimeout())

    assert success_ips == [ip4]
    assert interleave_val == 2
    established_connection.close()


async def test_tcp_connector_family_is_respected(
    loop: asyncio.AbstractEventLoop,
) -> None:
    conn = aiohttp.TCPConnector(family=socket.AF_INET)

    ip1 = "dead::beef::"
    ip2 = "192.168.1.1"
    ips = [ip1, ip2]
    addrs_tried = []

    req = ClientRequest(
        "GET",
        URL("https://mocked.host"),
        loop=loop,
    )

    async def _resolve_host(
        host: str, port: int, traces: object = None
    ) -> List[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in ips
        ]

    connected = False

    async def sock_connect(*args: Tuple[str, int], **kwargs: object) -> None:
        addr = args[1]
        addrs_tried.append(addr)

    async def create_connection(
        *args: object, sock: Optional[socket.socket] = None, **kwargs: object
    ) -> Tuple[ResponseHandler, ResponseHandler]:
        assert isinstance(sock, socket.socket)
        # Close the socket since we are not actually connecting
        # and we don't want to leak it.
        sock.close()

        nonlocal connected
        connected = True
        tr = create_mocked_conn(loop)
        pr = create_mocked_conn(loop)
        return tr, pr

    with mock.patch.object(
        conn, "_resolve_host", autospec=True, spec_set=True, side_effect=_resolve_host
    ):
        with mock.patch.object(
            conn._loop,
            "sock_connect",
            autospec=True,
            spec_set=True,
            side_effect=sock_connect,
        ):
            with mock.patch.object(
                conn._loop,
                "create_connection",
                autospec=True,
                spec_set=True,
                side_effect=create_connection,
            ):
                established_connection = await conn.connect(req, [], ClientTimeout())

                # We should only try the IPv4 address since we specified
                # the family to be AF_INET
                assert addrs_tried == [(ip2, 443)]

                assert connected

                established_connection.close()


@pytest.mark.parametrize(
    ("request_url"),
    [
        ("http://mocked.host"),
        ("https://mocked.host"),
    ],
)
async def test_tcp_connector_multiple_hosts_one_timeout(
    loop: asyncio.AbstractEventLoop,
    request_url: str,
) -> None:
    conn = aiohttp.TCPConnector()

    ip1 = "192.168.1.1"
    ip2 = "192.168.1.2"
    ips = [ip1, ip2]
    ips_tried = []
    ips_success = []
    timeout_error = False
    connected = False

    req = ClientRequest(
        "GET",
        URL(request_url),
        loop=loop,
    )

    async def _resolve_host(
        host: str, port: int, traces: object = None
    ) -> List[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in ips
        ]

    async def start_connection(
        addr_infos: Sequence[AddrInfoType],
        *,
        interleave: Optional[int] = None,
        **kwargs: object,
    ) -> socket.socket:
        nonlocal timeout_error

        addr_info = addr_infos[0]
        addr_info_addr = addr_info[-1]

        ip = addr_info_addr[0]
        ips_tried.append(ip)

        if ip == ip1:
            timeout_error = True
            raise asyncio.TimeoutError

        if ip == ip2:
            mock_socket = mock.create_autospec(
                socket.socket, spec_set=True, instance=True
            )
            mock_socket.getpeername.return_value = addr_info_addr
            return mock_socket  # type: ignore[no-any-return]

        assert False

    async def create_connection(
        *args: object, sock: Optional[socket.socket] = None, **kwargs: object
    ) -> Tuple[ResponseHandler, ResponseHandler]:
        nonlocal connected

        assert isinstance(sock, socket.socket)
        addr_info = sock.getpeername()
        ip = addr_info[0]
        ips_success.append(ip)
        connected = True

        # Close the socket since we are not actually connecting
        # and we don't want to leak it.
        sock.close()
        tr = create_mocked_conn(loop)
        pr = create_mocked_conn(loop)
        return tr, pr

    with mock.patch.object(
        conn, "_resolve_host", autospec=True, spec_set=True, side_effect=_resolve_host
    ), mock.patch.object(
        conn._loop,
        "create_connection",
        autospec=True,
        spec_set=True,
        side_effect=create_connection,
    ), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection", start_connection
    ):
        established_connection = await conn.connect(req, [], ClientTimeout())

    assert ips_tried == ips
    assert ips_success == [ip2]

    assert timeout_error
    assert connected

    established_connection.close()


async def test_tcp_connector_resolve_host(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.TCPConnector(use_dns_cache=True)

    res = await conn._resolve_host("localhost", 8080)
    assert res
    for rec in res:
        if rec["family"] == socket.AF_INET:
            assert rec["host"] == "127.0.0.1"
            assert rec["hostname"] == "localhost"
            assert rec["port"] == 8080
        else:
            assert rec["family"] == socket.AF_INET6
            assert rec["hostname"] == "localhost"
            assert rec["port"] == 8080
            if platform.system() == "Darwin":
                assert rec["host"] in ("::1", "fe80::1", "fe80::1%lo0")
            else:
                assert rec["host"] == "::1"


@pytest.fixture
def dns_response(loop: asyncio.AbstractEventLoop) -> Callable[[], Awaitable[List[str]]]:
    async def coro() -> List[str]:
        # simulates a network operation
        await asyncio.sleep(0)
        return ["127.0.0.1"]

    return coro


async def test_tcp_connector_dns_cache_not_expired(
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        await conn._resolve_host("localhost", 8080)
        await conn._resolve_host("localhost", 8080)
        m_resolver().resolve.assert_called_once_with("localhost", 8080, family=0)


async def test_tcp_connector_dns_cache_forever(
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        await conn._resolve_host("localhost", 8080)
        await conn._resolve_host("localhost", 8080)
        m_resolver().resolve.assert_called_once_with("localhost", 8080, family=0)


async def test_tcp_connector_use_dns_cache_disabled(
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
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
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        t = loop.create_task(conn._resolve_host("localhost", 8080))
        t2 = loop.create_task(conn._resolve_host("localhost", 8080))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        m_resolver().resolve.assert_called_once_with("localhost", 8080, family=0)
        t.cancel()
        t2.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.gather(t, t2)


async def test_tcp_connector_dns_throttle_requests_exception_spread(
    loop: asyncio.AbstractEventLoop,
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        e = Exception()
        m_resolver().resolve.side_effect = e
        r1 = loop.create_task(conn._resolve_host("localhost", 8080))
        r2 = loop.create_task(conn._resolve_host("localhost", 8080))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert r1.exception() == e
        assert r2.exception() == e


async def test_tcp_connector_dns_throttle_requests_cancelled_when_close(
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
) -> None:
    with mock.patch("aiohttp.connector.DefaultResolver") as m_resolver:
        conn = aiohttp.TCPConnector(use_dns_cache=True, ttl_dns_cache=10)
        m_resolver().resolve.return_value = dns_response()
        t = loop.create_task(conn._resolve_host("localhost", 8080))
        f = loop.create_task(conn._resolve_host("localhost", 8080))

        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await conn.close()

        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.gather(t, f)


@pytest.fixture
def dns_response_error(
    loop: asyncio.AbstractEventLoop,
) -> Callable[[], Awaitable[NoReturn]]:
    async def coro() -> NoReturn:
        # simulates a network operation
        await asyncio.sleep(0)
        raise socket.gaierror(-3, "Temporary failure in name resolution")

    return coro


async def test_tcp_connector_cancel_dns_error_captured(
    loop: asyncio.AbstractEventLoop,
    dns_response_error: Callable[[], Awaitable[NoReturn]],
) -> None:
    exception_handler_called = False

    def exception_handler(loop: asyncio.AbstractEventLoop, context: object) -> None:
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


async def test_tcp_connector_dns_tracing(
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
) -> None:
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
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
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
    loop: asyncio.AbstractEventLoop, dns_response: Callable[[], Awaitable[List[str]]]
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
        t = loop.create_task(conn._resolve_host("localhost", 8080, traces=traces))
        t1 = loop.create_task(conn._resolve_host("localhost", 8080, traces=traces))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        on_dns_cache_hit.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsCacheHitParams("localhost")
        )
        on_dns_cache_miss.assert_called_once_with(
            session, trace_config_ctx, aiohttp.TraceDnsCacheMissParams("localhost")
        )
        t.cancel()
        t1.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.gather(t, t1)


async def test_dns_error(loop: asyncio.AbstractEventLoop) -> None:
    connector = aiohttp.TCPConnector()
    with mock.patch.object(
        connector,
        "_resolve_host",
        autospec=True,
        spec_set=True,
        side_effect=OSError("dont take it serious"),
    ):
        req = ClientRequest("GET", URL("http://www.python.org"), loop=loop)

        with pytest.raises(aiohttp.ClientConnectorError):
            await connector.connect(req, [], ClientTimeout())


async def test_get_pop_empty_conns(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    # see issue #473
    conn = aiohttp.BaseConnector()
    assert await conn._get(key, []) is None
    assert not conn._conns


async def test_release_close_do_not_add_to_pool(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    # see issue #473
    conn = aiohttp.BaseConnector()

    proto = create_mocked_conn(loop, should_close=True)

    conn._acquired.add(proto)
    conn._release(key, proto)
    assert not conn._conns


async def test_release_close_do_not_delete_existing_connections(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto1 = create_mocked_conn(loop)

    conn = aiohttp.BaseConnector()
    conn._conns[key] = deque([(proto1, 1)])

    proto = create_mocked_conn(loop, should_close=True)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert conn._conns[key] == deque([(proto1, 1)])
    assert proto.close.called
    await conn.close()


async def test_release_not_started(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    proto = create_mocked_conn(should_close=False)
    conn._acquired.add(proto)
    conn._release(key, proto)
    # assert conn._conns == {key: [(proto, 10)]}
    rec = conn._conns[key]
    assert rec[0][0] == proto
    assert rec[0][1] == pytest.approx(loop.time(), abs=0.05)
    assert not proto.close.called
    await conn.close()


async def test_release_not_opened(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()

    proto = create_mocked_conn(loop)
    conn._acquired.add(proto)
    conn._release(key, proto)
    assert proto.close.called


async def test_connect(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost:80"), loop=loop)

    conn = aiohttp.BaseConnector()
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(conn, "_create_connection", create_mocked_conn(loop)) as m:
        m.return_value = loop.create_future()
        m.return_value.set_result(proto)

        connection = await conn.connect(req, [], ClientTimeout())
        assert not m.called
        assert connection._protocol is proto
        assert connection.transport is proto.transport
        assert isinstance(connection, Connection)
        connection.close()


async def test_connect_tracing(loop: asyncio.AbstractEventLoop) -> None:
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
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        conn2 = await conn.connect(req, traces, ClientTimeout())
        conn2.release()

        on_connection_create_start.assert_called_with(
            session, trace_config_ctx, aiohttp.TraceConnectionCreateStartParams()
        )
        on_connection_create_end.assert_called_with(
            session, trace_config_ctx, aiohttp.TraceConnectionCreateEndParams()
        )


@pytest.mark.parametrize(
    "signal",
    [
        "on_connection_create_start",
        "on_connection_create_end",
    ],
)
async def test_exception_during_connetion_create_tracing(
    loop: asyncio.AbstractEventLoop, signal: str
) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_signal = mock.AsyncMock(side_effect=asyncio.CancelledError)
    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    getattr(trace_config, signal).append(on_signal)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)
    key = req.connection_key
    conn = aiohttp.BaseConnector()
    assert not conn._acquired
    assert key not in conn._acquired_per_host

    with pytest.raises(asyncio.CancelledError), mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        await conn.connect(req, traces, ClientTimeout())

    assert not conn._acquired
    assert key not in conn._acquired_per_host


async def test_exception_during_connection_queued_tracing(
    loop: asyncio.AbstractEventLoop,
) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_signal = mock.AsyncMock(side_effect=asyncio.CancelledError)
    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_connection_queued_start.append(on_signal)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)
    key = req.connection_key
    conn = aiohttp.BaseConnector(limit=1)
    assert not conn._acquired
    assert key not in conn._acquired_per_host

    with pytest.raises(asyncio.CancelledError), mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        resp1 = await conn.connect(req, traces, ClientTimeout())
        assert resp1
        # 2nd connect request will be queued
        await conn.connect(req, traces, ClientTimeout())

    resp1.close()
    assert not conn._waiters
    assert not conn._acquired
    assert key not in conn._acquired_per_host


async def test_exception_during_connection_reuse_tracing(
    loop: asyncio.AbstractEventLoop,
) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    on_signal = mock.AsyncMock(side_effect=asyncio.CancelledError)
    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_connection_reuseconn.append(on_signal)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)
    key = req.connection_key
    conn = aiohttp.BaseConnector()
    assert not conn._acquired
    assert key not in conn._acquired_per_host

    with pytest.raises(asyncio.CancelledError), mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        resp = await conn.connect(req, traces, ClientTimeout())
        with mock.patch.object(resp.protocol, "should_close", False):
            resp.release()
        assert not conn._acquired
        assert key not in conn._acquired_per_host
        assert key in conn._conns

        await conn.connect(req, traces, ClientTimeout())

    assert not conn._acquired
    assert key not in conn._acquired_per_host


async def test_cancellation_during_waiting_for_free_connection(
    loop: asyncio.AbstractEventLoop,
) -> None:
    session = mock.Mock()
    trace_config_ctx = mock.Mock()
    waiter_wait_stated_future = loop.create_future()

    async def on_connection_queued_start(*args: object, **kwargs: object) -> None:
        waiter_wait_stated_future.set_result(None)

    trace_config = aiohttp.TraceConfig(
        trace_config_ctx_factory=mock.Mock(return_value=trace_config_ctx)
    )
    trace_config.on_connection_queued_start.append(on_connection_queued_start)
    trace_config.freeze()
    traces = [Trace(session, trace_config, trace_config.trace_config_ctx())]

    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)
    key = req.connection_key
    conn = aiohttp.BaseConnector(limit=1)
    assert not conn._acquired
    assert key not in conn._acquired_per_host

    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        resp1 = await conn.connect(req, traces, ClientTimeout())
        assert resp1
        # 2nd connect request will be queued
        task = asyncio.create_task(conn.connect(req, traces, ClientTimeout()))
        await waiter_wait_stated_future
        list(conn._waiters[key])[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    resp1.close()
    assert not conn._waiters
    assert not conn._acquired
    assert key not in conn._acquired_per_host


async def test_close_during_connect(loop: asyncio.AbstractEventLoop) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    fut = loop.create_future()
    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector()
    with mock.patch.object(conn, "_create_connection", lambda *args: fut):
        task = loop.create_task(conn.connect(req, [], ClientTimeout()))
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


async def test_cleanup(key: ConnectionKey) -> None:
    m1 = mock.Mock()
    m2 = mock.Mock()
    m1.is_connected.return_value = True
    m2.is_connected.return_value = False
    testset: Dict[ConnectionKey, Deque[Tuple[ResponseHandler, float]]] = {
        key: deque([(m1, 10), (m2, 300)]),
    }

    loop = mock.Mock()
    loop.time.return_value = 300
    conn = aiohttp.BaseConnector()
    conn._conns = testset
    existing_handle = conn._cleanup_handle = mock.Mock()

    with mock.patch("aiohttp.connector.monotonic", return_value=300):
        conn._cleanup()
    assert existing_handle.cancel.called
    assert conn._conns == {}
    assert conn._cleanup_handle is None


async def test_cleanup_close_ssl_transport(
    loop: asyncio.AbstractEventLoop, ssl_key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    transport = proto.transport
    testset: Dict[ConnectionKey, Deque[Tuple[ResponseHandler, float]]] = {
        ssl_key: deque([(proto, 10)])
    }

    loop = mock.Mock()
    new_time = asyncio.get_event_loop().time() + 300
    loop.time.return_value = new_time
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    conn._loop = loop
    conn._conns = testset
    existing_handle = conn._cleanup_handle = mock.Mock()

    with mock.patch("aiohttp.connector.monotonic", return_value=new_time):
        conn._cleanup()
    assert existing_handle.cancel.called
    assert conn._conns == {}
    assert conn._cleanup_closed_transports == [transport]


async def test_cleanup2(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    m = create_mocked_conn()
    m.is_connected.return_value = True
    testset: Dict[ConnectionKey, Deque[Tuple[ResponseHandler, float]]] = {
        key: deque([(m, 300)])
    }

    conn = aiohttp.BaseConnector(keepalive_timeout=10)
    conn._loop = mock.Mock()
    conn._loop.time.return_value = 300
    with mock.patch("aiohttp.connector.monotonic", return_value=300):
        conn._conns = testset
        conn._cleanup()
    assert conn._conns == testset

    assert conn._cleanup_handle is not None
    conn._loop.call_at.assert_called_with(310, mock.ANY, mock.ANY)
    await conn.close()


async def test_cleanup3(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    m = create_mocked_conn(loop)
    m.is_connected.return_value = True
    testset: Dict[ConnectionKey, List[Tuple[ResponseHandler, float]]] = {
        key: deque([(m, 290.1), (create_mocked_conn(loop), 305.1)])
    }

    conn = aiohttp.BaseConnector(keepalive_timeout=10)
    conn._loop = mock.Mock()
    conn._loop.time.return_value = 308.5
    conn._conns = testset

    with mock.patch("aiohttp.connector.monotonic", return_value=308.5):
        conn._cleanup()

    assert conn._conns == {key: deque([testset[key][1]])}

    assert conn._cleanup_handle is not None
    conn._loop.call_at.assert_called_with(319, mock.ANY, mock.ANY)
    await conn.close()


async def test_cleanup_closed(
    loop: asyncio.AbstractEventLoop, mocker: MockerFixture
) -> None:
    if not hasattr(loop, "__dict__"):
        pytest.skip("can not override loop attributes")

    m = mocker.spy(loop, "call_at")
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)

    tr = mock.Mock()
    conn._cleanup_closed_handle = cleanup_closed_handle = mock.Mock()
    conn._cleanup_closed_transports = [tr]
    conn._cleanup_closed()
    assert tr.abort.called
    assert not conn._cleanup_closed_transports
    assert m.called
    assert cleanup_closed_handle.cancel.called


async def test_cleanup_closed_disabled(
    loop: asyncio.AbstractEventLoop, mocker: MockerFixture
) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=False)

    tr = mock.Mock()
    conn._cleanup_closed_transports = [tr]
    conn._cleanup_closed()
    assert tr.abort.called
    assert not conn._cleanup_closed_transports


async def test_tcp_connector_ctor(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.TCPConnector()
    assert conn._ssl is True

    assert conn.use_dns_cache
    assert conn.family == 0


async def test_tcp_connector_allowed_protocols(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.TCPConnector()
    assert conn.allowed_protocol_schema_set == {"", "tcp", "http", "https", "ws", "wss"}


async def test_invalid_ssl_param() -> None:
    with pytest.raises(TypeError):
        aiohttp.TCPConnector(ssl=object())  # type: ignore[arg-type]


async def test_tcp_connector_ctor_fingerprint_valid(
    loop: asyncio.AbstractEventLoop,
) -> None:
    valid = aiohttp.Fingerprint(hashlib.sha256(b"foo").digest())
    conn = aiohttp.TCPConnector(ssl=valid)
    assert conn._ssl is valid


async def test_insecure_fingerprint_md5(loop: asyncio.AbstractEventLoop) -> None:
    with pytest.raises(ValueError):
        aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(hashlib.md5(b"foo").digest()))


async def test_insecure_fingerprint_sha1(loop: asyncio.AbstractEventLoop) -> None:
    with pytest.raises(ValueError):
        aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(hashlib.sha1(b"foo").digest()))


async def test_tcp_connector_clear_dns_cache(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.TCPConnector()
    h1: ResolveResult = {
        "hostname": "a",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }
    h2: ResolveResult = {
        "hostname": "a",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }
    hosts = [h1, h2]
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


async def test_tcp_connector_clear_dns_cache_bad_args(
    loop: asyncio.AbstractEventLoop,
) -> None:
    conn = aiohttp.TCPConnector()
    with pytest.raises(ValueError):
        conn.clear_dns_cache("localhost")


async def test___get_ssl_context1() -> None:
    conn = aiohttp.TCPConnector()
    req = mock.Mock()
    req.is_ssl.return_value = False
    assert conn._get_ssl_context(req) is None


async def test___get_ssl_context2() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    conn = aiohttp.TCPConnector()
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = ctx
    assert conn._get_ssl_context(req) is ctx


async def test___get_ssl_context3() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    conn = aiohttp.TCPConnector(ssl=ctx)
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = True
    assert conn._get_ssl_context(req) is ctx


async def test___get_ssl_context4() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    conn = aiohttp.TCPConnector(ssl=ctx)
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = False
    assert conn._get_ssl_context(req) is _SSL_CONTEXT_UNVERIFIED


async def test___get_ssl_context5() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    conn = aiohttp.TCPConnector(ssl=ctx)
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = aiohttp.Fingerprint(hashlib.sha256(b"1").digest())
    assert conn._get_ssl_context(req) is _SSL_CONTEXT_UNVERIFIED


async def test___get_ssl_context6() -> None:
    conn = aiohttp.TCPConnector()
    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = True
    assert conn._get_ssl_context(req) is _SSL_CONTEXT_VERIFIED


async def test_ssl_context_once() -> None:
    """Test the ssl context is created only once and shared between connectors."""
    conn1 = aiohttp.TCPConnector()
    conn2 = aiohttp.TCPConnector()
    conn3 = aiohttp.TCPConnector()

    req = mock.Mock()
    req.is_ssl.return_value = True
    req.ssl = True
    assert conn1._get_ssl_context(req) is _SSL_CONTEXT_VERIFIED
    assert conn2._get_ssl_context(req) is _SSL_CONTEXT_VERIFIED
    assert conn3._get_ssl_context(req) is _SSL_CONTEXT_VERIFIED


async def test_close_twice(loop: asyncio.AbstractEventLoop, key: ConnectionKey) -> None:
    proto: ResponseHandler = create_mocked_conn(loop)

    conn = aiohttp.BaseConnector()
    conn._conns[key] = deque([(proto, 0)])
    await conn.close()

    assert not conn._conns
    assert proto.close.called  # type: ignore[attr-defined]
    assert conn.closed

    conn._conns = "Invalid"  # type: ignore[assignment]  # fill with garbage
    await conn.close()
    assert conn.closed


async def test_close_cancels_cleanup_handle(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector()
    conn._release(key, create_mocked_conn(should_close=False))
    assert conn._cleanup_handle is not None
    await conn.close()
    assert conn._cleanup_handle is None


async def test_close_cancels_resolve_host(loop: asyncio.AbstractEventLoop) -> None:
    cancelled = False

    async def delay_resolve(*args: object, **kwargs: object) -> None:
        """Delay resolve() task in order to test cancellation."""
        nonlocal cancelled
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled = True
            raise

    conn = aiohttp.TCPConnector()
    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )
    with mock.patch.object(conn._resolver, "resolve", delay_resolve):
        t = asyncio.create_task(conn.connect(req, [], ClientTimeout()))
        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # We now have a task being tracked and can ensure that .close() cancels it.
        assert len(conn._resolve_host_tasks) == 1
        await conn.close()
        assert cancelled
        assert len(conn._resolve_host_tasks) == 0

        with suppress(asyncio.CancelledError):
            await t


async def test_multiple_dns_resolution_requests_success(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Verify that multiple DNS resolution requests are handled correctly."""

    async def delay_resolve(*args: object, **kwargs: object) -> List[ResolveResult]:
        """Delayed resolve() task."""
        for _ in range(3):
            await asyncio.sleep(0)
        return [
            {
                "hostname": "localhost",
                "host": "127.0.0.1",
                "port": 80,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            },
        ]

    conn = aiohttp.TCPConnector(force_close=True)
    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )
    with mock.patch.object(conn._resolver, "resolve", delay_resolve), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        side_effect=OSError(1, "Forced connection to fail"),
    ):
        task1 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # Ensure the task is running
        assert len(conn._resolve_host_tasks) == 1

        task2 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))
        task3 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        with pytest.raises(
            aiohttp.ClientConnectorError, match="Forced connection to fail"
        ):
            await task1

        # Verify the the task is finished
        assert len(conn._resolve_host_tasks) == 0

        with pytest.raises(
            aiohttp.ClientConnectorError, match="Forced connection to fail"
        ):
            await task2
        with pytest.raises(
            aiohttp.ClientConnectorError, match="Forced connection to fail"
        ):
            await task3


async def test_multiple_dns_resolution_requests_failure(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Verify that DNS resolution failure for multiple requests is handled correctly."""

    async def delay_resolve(*args: object, **kwargs: object) -> List[ResolveResult]:
        """Delayed resolve() task."""
        for _ in range(3):
            await asyncio.sleep(0)
        raise OSError(None, "DNS Resolution mock failure")

    conn = aiohttp.TCPConnector(force_close=True)
    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )
    with mock.patch.object(conn._resolver, "resolve", delay_resolve), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        side_effect=OSError(1, "Forced connection to fail"),
    ):
        task1 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # Ensure the task is running
        assert len(conn._resolve_host_tasks) == 1

        task2 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))
        task3 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task1

        # Verify the the task is finished
        assert len(conn._resolve_host_tasks) == 0

        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task2
        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task3


async def test_multiple_dns_resolution_requests_cancelled(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Verify that DNS resolution cancellation does not affect other tasks."""

    async def delay_resolve(*args: object, **kwargs: object) -> List[ResolveResult]:
        """Delayed resolve() task."""
        for _ in range(3):
            await asyncio.sleep(0)
        raise OSError(None, "DNS Resolution mock failure")

    conn = aiohttp.TCPConnector(force_close=True)
    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )
    with mock.patch.object(conn._resolver, "resolve", delay_resolve), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        side_effect=OSError(1, "Forced connection to fail"),
    ):
        task1 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # Ensure the task is running
        assert len(conn._resolve_host_tasks) == 1

        task2 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))
        task3 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        task1.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task1

        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task2
        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task3

        # Verify the the task is finished
        assert len(conn._resolve_host_tasks) == 0


async def test_multiple_dns_resolution_requests_first_cancelled(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Verify that first DNS resolution cancellation does not make other resolutions fail."""

    async def delay_resolve(*args: object, **kwargs: object) -> List[ResolveResult]:
        """Delayed resolve() task."""
        for _ in range(3):
            await asyncio.sleep(0)
        return [
            {
                "hostname": "localhost",
                "host": "127.0.0.1",
                "port": 80,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            },
        ]

    conn = aiohttp.TCPConnector(force_close=True)
    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )
    with mock.patch.object(conn._resolver, "resolve", delay_resolve), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        side_effect=OSError(1, "Forced connection to fail"),
    ):
        task1 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # Ensure the task is running
        assert len(conn._resolve_host_tasks) == 1

        task2 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))
        task3 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        task1.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task1

        # The second and third tasks should still make the connection
        # even if the first one is cancelled
        with pytest.raises(
            aiohttp.ClientConnectorError, match="Forced connection to fail"
        ):
            await task2
        with pytest.raises(
            aiohttp.ClientConnectorError, match="Forced connection to fail"
        ):
            await task3

        # Verify the the task is finished
        assert len(conn._resolve_host_tasks) == 0


async def test_multiple_dns_resolution_requests_first_fails_second_successful(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Verify that first DNS resolution fails the first time and is successful the second time."""
    attempt = 0

    async def delay_resolve(*args: object, **kwargs: object) -> List[ResolveResult]:
        """Delayed resolve() task."""
        nonlocal attempt
        for _ in range(3):
            await asyncio.sleep(0)
        attempt += 1
        if attempt == 1:
            raise OSError(None, "DNS Resolution mock failure")
        return [
            {
                "hostname": "localhost",
                "host": "127.0.0.1",
                "port": 80,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            },
        ]

    conn = aiohttp.TCPConnector(force_close=True)
    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )
    with mock.patch.object(conn._resolver, "resolve", delay_resolve), mock.patch(
        "aiohttp.connector.aiohappyeyeballs.start_connection",
        side_effect=OSError(1, "Forced connection to fail"),
    ):
        task1 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # Ensure the task is running
        assert len(conn._resolve_host_tasks) == 1

        task2 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))

        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task1

        assert len(conn._resolve_host_tasks) == 0
        # The second task should also get the dns resolution failure
        with pytest.raises(
            aiohttp.ClientConnectorError, match="DNS Resolution mock failure"
        ):
            await task2

        # The third task is created after the resolution finished so
        # it should try again and succeed
        task3 = asyncio.create_task(conn.connect(req, [], ClientTimeout()))
        # Let it create the internal task
        await asyncio.sleep(0)
        # Let that task start running
        await asyncio.sleep(0)

        # Ensure the task is running
        assert len(conn._resolve_host_tasks) == 1

        with pytest.raises(
            aiohttp.ClientConnectorError, match="Forced connection to fail"
        ):
            await task3

        # Verify the the task is finished
        assert len(conn._resolve_host_tasks) == 0


async def test_close_abort_closed_transports(loop: asyncio.AbstractEventLoop) -> None:
    tr = mock.Mock()

    conn = aiohttp.BaseConnector()
    conn._cleanup_closed_transports.append(tr)
    await conn.close()

    assert not conn._cleanup_closed_transports
    assert tr.abort.called
    assert conn.closed


async def test_close_cancels_cleanup_closed_handle(
    loop: asyncio.AbstractEventLoop,
) -> None:
    conn = aiohttp.BaseConnector(enable_cleanup_closed=True)
    assert conn._cleanup_closed_handle is not None
    await conn.close()
    assert conn._cleanup_closed_handle is None


async def test_ctor_with_default_loop(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()
    assert loop is conn._loop


async def test_base_connector_allows_high_level_protocols(
    loop: asyncio.AbstractEventLoop,
) -> None:
    conn = aiohttp.BaseConnector()
    assert conn.allowed_protocol_schema_set == {
        "",
        "http",
        "https",
        "ws",
        "wss",
    }


async def test_connect_with_limit(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest(
        "GET", URL("http://localhost:80"), loop=loop, response_class=mock.Mock()
    )

    conn = aiohttp.BaseConnector(limit=1)
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        connection1 = await conn.connect(req, [], ClientTimeout())
        assert connection1._protocol == proto

        assert 1 == len(conn._acquired)
        assert proto in conn._acquired
        assert key in conn._acquired_per_host
        assert proto in conn._acquired_per_host[key]

        acquired = False

        async def f() -> None:
            nonlocal acquired
            connection2 = await conn.connect(req, [], ClientTimeout())
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
        await task  # type: ignore[unreachable]
        await conn.close()


async def test_connect_queued_operation_tracing(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
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
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        connection1 = await conn.connect(req, traces, ClientTimeout())

        async def f() -> None:
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


async def test_connect_reuseconn_tracing(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
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
    conn._conns[key] = deque([(proto, loop.time())])
    conn2 = await conn.connect(req, traces, ClientTimeout())
    conn2.release()

    on_connection_reuseconn.assert_called_with(
        session, trace_config_ctx, aiohttp.TraceConnectionReuseconnParams()
    )
    await conn.close()


async def test_connect_with_limit_and_limit_per_host(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1000, limit_per_host=1)
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        acquired = False
        connection1 = await conn.connect(req, [], ClientTimeout())

        async def f() -> None:
            nonlocal acquired
            connection2 = await conn.connect(req, [], ClientTimeout())
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
        await task  # type: ignore[unreachable]
        await conn.close()


async def test_connect_with_no_limit_and_limit_per_host(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost1:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=0, limit_per_host=1)
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        acquired = False
        connection1 = await conn.connect(req, [], ClientTimeout())

        async def f() -> None:
            nonlocal acquired
            connection2 = await conn.connect(req, [], ClientTimeout())
            acquired = True
            connection2.release()

        task = loop.create_task(f())

        await asyncio.sleep(0.01)
        assert not acquired
        connection1.release()
        await asyncio.sleep(0)
        assert acquired
        await task  # type: ignore[unreachable]
        await conn.close()


async def test_connect_with_no_limits(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://localhost:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=0, limit_per_host=0)
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        acquired = False
        connection1 = await conn.connect(req, [], ClientTimeout())

        async def f() -> None:
            nonlocal acquired
            connection2 = await conn.connect(req, [], ClientTimeout())
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


async def test_connect_with_limit_cancelled(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        connection = await conn.connect(req, [], ClientTimeout())
        assert connection._protocol == proto
        assert connection.transport == proto.transport

        assert 1 == len(conn._acquired)

        with pytest.raises(asyncio.TimeoutError):
            # limit exhausted
            await asyncio.wait_for(conn.connect(req, [], ClientTimeout()), 0.01)
        connection.close()

        await conn.close()


async def test_connect_with_capacity_release_waiters(
    loop: asyncio.AbstractEventLoop,
) -> None:
    async def check_with_exc(err: Exception) -> None:
        conn = aiohttp.BaseConnector(limit=1)
        with mock.patch.object(
            conn, "_create_connection", autospec=True, spec_set=True, side_effect=err
        ):
            with pytest.raises(Exception):
                req = mock.Mock()
                await conn.connect(req, [], ClientTimeout())

            assert not conn._waiters

    await check_with_exc(OSError(1, "permission error"))
    await check_with_exc(RuntimeError())
    await check_with_exc(asyncio.TimeoutError())


async def test_connect_with_limit_concurrent(loop: asyncio.AbstractEventLoop) -> None:
    proto = create_mocked_conn(loop)
    proto.should_close = False
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    max_connections = 2
    num_connections = 0

    conn = aiohttp.BaseConnector(limit=max_connections)

    # Use a real coroutine for _create_connection; a mock would mask
    # problems that only happen when the method yields.

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        nonlocal num_connections
        num_connections += 1
        await asyncio.sleep(0)

        # Make a new transport mock each time because acquired
        # transports are stored in a set. Reusing the same object
        # messes with the count.
        proto = create_mocked_conn(loop, should_close=False)
        proto.is_connected.return_value = True

        return proto

    # Simulate something like a crawler. It opens a connection, does
    # something with it, closes it, then creates tasks that make more
    # connections and waits for them to finish. The crawler is started
    # with multiple concurrent requests and stops when it hits a
    # predefined maximum number of requests.

    max_requests = 50
    num_requests = 0
    start_requests = max_connections + 1

    async def f(start: bool = True) -> None:
        nonlocal num_requests
        if num_requests == max_requests:
            return
        num_requests += 1
        if not start:
            connection = await conn.connect(req, [], ClientTimeout())
            await asyncio.sleep(0)
            connection.release()
            await asyncio.sleep(0)
        tasks = [loop.create_task(f(start=False)) for i in range(start_requests)]
        await asyncio.wait(tasks)

    with mock.patch.object(conn, "_create_connection", create_connection):
        await f()
        await conn.close()

        assert max_connections == num_connections


async def test_connect_waiters_cleanup(loop: asyncio.AbstractEventLoop) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    with mock.patch.object(conn, "_available_connections", return_value=0):
        t = loop.create_task(conn.connect(req, [], ClientTimeout()))

        await asyncio.sleep(0)
        assert conn._waiters.keys()

        t.cancel()
        await asyncio.sleep(0)
        assert not conn._waiters.keys()


async def test_connect_waiters_cleanup_key_error(
    loop: asyncio.AbstractEventLoop,
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    with mock.patch.object(
        conn, "_available_connections", autospec=True, spec_set=True, return_value=0
    ):
        t = loop.create_task(conn.connect(req, [], ClientTimeout()))

        await asyncio.sleep(0)
        assert conn._waiters.keys()

        # we delete the entry explicitly before the
        # canceled connection grabs the loop again, we
        # must expect a none failure termination
        conn._waiters.clear()
        t.cancel()
        await asyncio.sleep(0)
        assert not conn._waiters.keys() == []


async def test_close_with_acquired_connection(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("http://host:80"), loop=loop)

    conn = aiohttp.BaseConnector(limit=1)
    conn._conns[key] = deque([(proto, loop.time())])
    with mock.patch.object(
        conn, "_create_connection", autospec=True, spec_set=True, return_value=proto
    ):
        connection = await conn.connect(req, [], ClientTimeout())

        assert 1 == len(conn._acquired)
        await conn.close()
        assert 0 == len(conn._acquired)
        assert conn.closed
        proto.close.assert_called_with()

        assert not connection.closed
        connection.close()
        assert connection.closed


async def test_default_force_close(loop: asyncio.AbstractEventLoop) -> None:
    connector = aiohttp.BaseConnector()
    assert not connector.force_close


async def test_limit_property(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector(limit=15)
    assert 15 == conn.limit

    await conn.close()


async def test_limit_per_host_property(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector(limit_per_host=15)
    assert 15 == conn.limit_per_host

    await conn.close()


async def test_limit_property_default(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()
    assert conn.limit == 100
    await conn.close()


async def test_limit_per_host_property_default(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector()
    assert conn.limit_per_host == 0
    await conn.close()


async def test_force_close_and_explicit_keep_alive(
    loop: asyncio.AbstractEventLoop,
) -> None:
    aiohttp.BaseConnector(force_close=True)
    aiohttp.BaseConnector(force_close=True, keepalive_timeout=None)
    with pytest.raises(ValueError):
        aiohttp.BaseConnector(keepalive_timeout=30, force_close=True)


async def test_error_on_connection(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector(limit=1)

    req = mock.Mock()
    req.connection_key = key
    proto = create_mocked_conn(loop)
    i = 0

    fut = loop.create_future()
    exc = OSError()

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        nonlocal i
        i += 1
        if i == 1:
            await fut
            raise exc
        elif i == 2:
            return proto
        assert False

    with mock.patch.object(conn, "_create_connection", create_connection):
        t1 = loop.create_task(conn.connect(req, [], ClientTimeout()))
        t2 = loop.create_task(conn.connect(req, [], ClientTimeout()))
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


async def test_cancelled_waiter(loop: asyncio.AbstractEventLoop) -> None:
    conn = aiohttp.BaseConnector(limit=1)
    req = mock.Mock()
    req.connection_key = "key"
    proto = create_mocked_conn(loop)

    async def create_connection(req: object, traces: object = None) -> ResponseHandler:
        await asyncio.sleep(1)
        return proto

    with mock.patch.object(conn, "_create_connection", create_connection):
        conn._acquired.add(proto)

        conn2 = loop.create_task(conn.connect(req, [], ClientTimeout()))
        await asyncio.sleep(0)
        conn2.cancel()

        with pytest.raises(asyncio.CancelledError):
            await conn2


async def test_error_on_connection_with_cancelled_waiter(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    conn = aiohttp.BaseConnector(limit=1)

    req = mock.Mock()
    req.connection_key = key
    proto = create_mocked_conn()
    i = 0

    fut1 = loop.create_future()
    fut2 = loop.create_future()
    exc = OSError()

    async def create_connection(
        req: object, traces: object, timeout: object
    ) -> ResponseHandler:
        nonlocal i
        i += 1
        if i == 1:
            await fut1
            raise exc
        if i == 2:
            await fut2
        elif i == 3:
            return proto
        assert False

    with mock.patch.object(conn, "_create_connection", create_connection):
        t1 = loop.create_task(conn.connect(req, [], ClientTimeout()))
        t2 = loop.create_task(conn.connect(req, [], ClientTimeout()))
        t3 = loop.create_task(conn.connect(req, [], ClientTimeout()))
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


async def test_tcp_connector(
    aiohttp_client: AiohttpClient, loop: asyncio.AbstractEventLoop
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    client = await aiohttp_client(app)

    r = await client.get("/")
    assert r.status == 200


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="requires UNIX sockets")
async def test_unix_connector_not_found(loop: asyncio.AbstractEventLoop) -> None:
    connector = aiohttp.UnixConnector("/" + uuid.uuid4().hex)

    req = ClientRequest("GET", URL("http://www.python.org"), loop=loop)
    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, [], ClientTimeout())


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="requires UNIX sockets")
async def test_unix_connector_permission(loop: asyncio.AbstractEventLoop) -> None:
    m = make_mocked_coro(raise_exception=PermissionError())
    with mock.patch.object(loop, "create_unix_connection", m):
        connector = aiohttp.UnixConnector("/" + uuid.uuid4().hex)

        req = ClientRequest("GET", URL("http://www.python.org"), loop=loop)
        with pytest.raises(aiohttp.ClientConnectorError):
            await connector.connect(req, [], ClientTimeout())


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector_wrong_loop(
    selector_loop: asyncio.AbstractEventLoop, pipe_name: str
) -> None:
    with pytest.raises(RuntimeError):
        aiohttp.NamedPipeConnector(pipe_name)


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector_not_found(
    proactor_loop: asyncio.AbstractEventLoop, pipe_name: str
) -> None:
    asyncio.set_event_loop(proactor_loop)
    connector = aiohttp.NamedPipeConnector(pipe_name)

    req = ClientRequest("GET", URL("http://www.python.org"), loop=proactor_loop)
    with pytest.raises(aiohttp.ClientConnectorError):
        await connector.connect(req, [], ClientTimeout())


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector_permission(
    proactor_loop: asyncio.AbstractEventLoop, pipe_name: str
) -> None:
    m = make_mocked_coro(raise_exception=PermissionError())
    with mock.patch.object(proactor_loop, "create_pipe_connection", m):
        asyncio.set_event_loop(proactor_loop)
        connector = aiohttp.NamedPipeConnector(pipe_name)

        req = ClientRequest("GET", URL("http://www.python.org"), loop=proactor_loop)
        with pytest.raises(aiohttp.ClientConnectorError):
            await connector.connect(req, [], ClientTimeout())


async def test_default_use_dns_cache() -> None:
    conn = aiohttp.TCPConnector()
    assert conn.use_dns_cache


async def test_resolver_not_called_with_address_is_ip(
    loop: asyncio.AbstractEventLoop,
) -> None:
    resolver = mock.MagicMock()
    connector = aiohttp.TCPConnector(resolver=resolver)

    req = ClientRequest(
        "GET",
        URL(f"http://127.0.0.1:{unused_port()}"),
        loop=loop,
        response_class=mock.Mock(),
    )

    with pytest.raises(OSError):
        await connector.connect(req, [], ClientTimeout())

    resolver.resolve.assert_not_called()


async def test_tcp_connector_raise_connector_ssl_error(
    aiohttp_server: AiohttpServer, ssl_ctx: ssl.SSLContext
) -> None:
    async def handler(request: web.Request) -> NoReturn:
        assert False

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


@pytest.mark.parametrize(
    "host",
    (
        pytest.param("127.0.0.1", id="ip address"),
        pytest.param("localhost", id="domain name"),
        pytest.param("localhost.", id="fully-qualified domain name"),
        pytest.param(
            "localhost...", id="fully-qualified domain name with multiple trailing dots"
        ),
        pytest.param("príklad.localhost.", id="idna fully-qualified domain name"),
    ),
)
async def test_tcp_connector_do_not_raise_connector_ssl_error(
    aiohttp_server: AiohttpServer,
    ssl_ctx: ssl.SSLContext,
    client_ssl_ctx: ssl.SSLContext,
    host: str,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)

    srv = await aiohttp_server(app, ssl=ssl_ctx)
    port = unused_port()
    conn = aiohttp.TCPConnector(local_addr=("127.0.0.1", port))

    # resolving something.localhost with the real DNS resolver does not work on macOS, so we have a stub.
    async def _resolve_host(
        host: str, port: int, traces: object = None
    ) -> List[ResolveResult]:
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            },
            {
                "hostname": host,
                "host": "::1",
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            },
        ]

    with mock.patch.object(
        conn, "_resolve_host", autospec=True, spec_set=True, side_effect=_resolve_host
    ):
        session = aiohttp.ClientSession(connector=conn)
        url = srv.make_url("/")

        r = await session.get(url.with_host(host), ssl=client_ssl_ctx)

        r.release()
        first_conn = next(iter(conn._conns.values()))[0][0]

        assert first_conn.transport is not None
        try:
            _sslcontext = first_conn.transport._ssl_protocol._sslcontext  # type: ignore[attr-defined]
        except AttributeError:
            _sslcontext = first_conn.transport._sslcontext  # type: ignore[attr-defined]

        assert _sslcontext is client_ssl_ctx
        r.close()

        await session.close()
        await conn.close()


async def test_tcp_connector_uses_provided_local_addr(
    aiohttp_server: AiohttpServer,
) -> None:
    async def handler(request: web.Request) -> web.Response:
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
    assert first_conn.transport is not None
    assert first_conn.transport.get_extra_info("sockname") == ("127.0.0.1", port)
    r.close()
    await session.close()
    await conn.close()


async def test_unix_connector(
    unix_server: Callable[[web.Application], Awaitable[None]], unix_sockname: str
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    await unix_server(app)

    url = "http://127.0.0.1/"

    connector = aiohttp.UnixConnector(unix_sockname)
    assert unix_sockname == connector.path
    assert connector.allowed_protocol_schema_set == {
        "",
        "http",
        "https",
        "ws",
        "wss",
        "unix",
    }

    session = ClientSession(connector=connector)
    r = await session.get(url)
    assert r.status == 200
    r.close()
    await session.close()


@pytest.mark.skipif(
    platform.system() != "Windows", reason="Proactor Event loop present only in Windows"
)
async def test_named_pipe_connector(
    proactor_loop: asyncio.AbstractEventLoop,
    named_pipe_server: Callable[[web.Application], Awaitable[None]],
    pipe_name: str,
) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response()

    app = web.Application()
    app.router.add_get("/", handler)
    await named_pipe_server(app)

    url = "http://this-does-not-matter.com"

    connector = aiohttp.NamedPipeConnector(pipe_name)
    assert pipe_name == connector.path
    assert connector.allowed_protocol_schema_set == {
        "",
        "http",
        "https",
        "ws",
        "wss",
        "npipe",
    }

    session = ClientSession(connector=connector)
    r = await session.get(url)
    assert r.status == 200
    r.close()
    await session.close()


class TestDNSCacheTable:
    host1 = ("localhost", 80)
    host2 = ("foo", 80)
    result1: ResolveResult = {
        "hostname": "localhost",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }
    result2: ResolveResult = {
        "hostname": "foo",
        "host": "127.0.0.2",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }

    @pytest.fixture
    def dns_cache_table(self) -> _DNSCacheTable:
        return _DNSCacheTable()

    def test_next_addrs_basic(self, dns_cache_table: _DNSCacheTable) -> None:
        dns_cache_table.add(self.host1, [self.result1])
        dns_cache_table.add(self.host2, [self.result2])

        addrs = dns_cache_table.next_addrs(self.host1)
        assert addrs == [self.result1]
        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [self.result2]
        with pytest.raises(KeyError):
            dns_cache_table.next_addrs(("no-such-host", 80))

    def test_remove(self, dns_cache_table: _DNSCacheTable) -> None:
        dns_cache_table.add(self.host1, [self.result1])
        dns_cache_table.remove(self.host1)
        with pytest.raises(KeyError):
            dns_cache_table.next_addrs(self.host1)

    def test_clear(self, dns_cache_table: _DNSCacheTable) -> None:
        dns_cache_table.add(self.host1, [self.result1])
        dns_cache_table.clear()
        with pytest.raises(KeyError):
            dns_cache_table.next_addrs(self.host1)

    def test_not_expired_ttl_None(self, dns_cache_table: _DNSCacheTable) -> None:
        dns_cache_table.add(self.host1, [self.result1])
        assert not dns_cache_table.expired(self.host1)

    def test_not_expired_ttl(self) -> None:
        dns_cache_table = _DNSCacheTable(ttl=0.1)
        dns_cache_table.add(self.host1, [self.result1])
        assert not dns_cache_table.expired(self.host1)

    def test_expired_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dns_cache_table = _DNSCacheTable(ttl=1)
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 1)
        dns_cache_table.add(self.host1, [self.result1])
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 2)
        assert not dns_cache_table.expired(self.host1)
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 3)
        assert dns_cache_table.expired(self.host1)

    def test_never_expire(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dns_cache_table = _DNSCacheTable(ttl=None)
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 1)
        dns_cache_table.add(self.host1, [self.result1])
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 10000000)
        assert not dns_cache_table.expired(self.host1)

    def test_always_expire(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dns_cache_table = _DNSCacheTable(ttl=0)
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 1)
        dns_cache_table.add(self.host1, [self.result1])
        monkeypatch.setattr("aiohttp.connector.monotonic", lambda: 1.00001)
        assert dns_cache_table.expired(self.host1)

    def test_next_addrs(self, dns_cache_table: _DNSCacheTable) -> None:
        result3: ResolveResult = {
            "hostname": "foo",
            "host": "127.0.0.3",
            "port": 80,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": socket.AI_NUMERICHOST,
        }
        dns_cache_table.add(self.host2, [self.result1, self.result2, result3])

        # Each calls to next_addrs return the hosts using
        # a round robin strategy.
        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [self.result1, self.result2, result3]

        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [self.result2, result3, self.result1]

        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [result3, self.result1, self.result2]

        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [self.result1, self.result2, result3]

    def test_next_addrs_single(self, dns_cache_table: _DNSCacheTable) -> None:
        dns_cache_table.add(self.host2, [self.result1])

        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [self.result1]

        addrs = dns_cache_table.next_addrs(self.host2)
        assert addrs == [self.result1]


async def test_connector_cache_trace_race() -> None:
    class DummyTracer(Trace):
        def __init__(self) -> None:
            """Dummy"""

        async def send_dns_cache_hit(self, *args: object, **kwargs: object) -> None:
            connector._cached_hosts.remove(("", 0))

    token: ResolveResult = {
        "hostname": "localhost",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }
    connector = TCPConnector()
    connector._cached_hosts.add(("", 0), [token])

    traces = [DummyTracer()]
    assert await connector._resolve_host("", 0, traces) == [token]


async def test_connector_throttle_trace_race(loop: asyncio.AbstractEventLoop) -> None:
    key = ("", 0)
    token: ResolveResult = {
        "hostname": "localhost",
        "host": "127.0.0.1",
        "port": 80,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }

    class DummyTracer(Trace):
        def __init__(self) -> None:
            """Dummy"""

        async def send_dns_cache_hit(self, *args: object, **kwargs: object) -> None:
            futures = connector._throttle_dns_futures.pop(key)
            for fut in futures:
                fut.set_result(None)
            connector._cached_hosts.add(key, [token])

    connector = TCPConnector()
    connector._throttle_dns_futures[key] = set()
    traces = [DummyTracer()]
    assert await connector._resolve_host("", 0, traces) == [token]


async def test_connector_does_not_remove_needed_waiters(
    loop: asyncio.AbstractEventLoop, key: ConnectionKey
) -> None:
    proto = create_mocked_conn(loop)
    proto.is_connected.return_value = True

    req = ClientRequest("GET", URL("https://localhost:80"), loop=loop)
    connection_key = req.connection_key

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
        list(connector._waiters[connection_key])[0].set_result(None)
        del connector._waiters[connection_key]
        connector._waiters[connection_key][dummy_waiter] = None

    connector = aiohttp.BaseConnector()
    with mock.patch.object(
        connector,
        "_available_connections",
        autospec=True,
        spec_set=True,
        side_effect=[0, 1, 1, 1],
    ):
        connector._conns[key] = [(proto, loop.time())]
        with mock.patch.object(
            connector,
            "_create_connection",
            autospec=True,
            spec_set=True,
            return_value=proto,
        ):
            dummy_waiter = loop.create_future()

            await asyncio.gather(
                await_connection_and_check_waiters(),
                allow_connection_and_add_dummy_waiter(),
            )

            await connector.close()


def test_connector_multiple_event_loop() -> None:
    """Test the connector with multiple event loops."""

    async def async_connect() -> Literal[True]:
        conn = aiohttp.TCPConnector()
        loop = asyncio.get_running_loop()
        req = ClientRequest("GET", URL("https://127.0.0.1"), loop=loop)
        with suppress(aiohttp.ClientConnectorError):
            with mock.patch.object(
                conn._loop,
                "create_connection",
                autospec=True,
                spec_set=True,
                side_effect=ssl.CertificateError,
            ):
                await conn.connect(req, [], ClientTimeout())
        return True

    def test_connect() -> Literal[True]:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(async_connect())
        finally:
            loop.close()

    with futures.ThreadPoolExecutor() as executor:
        res_list = [executor.submit(test_connect) for _ in range(2)]
        raw_response_list = [res.result() for res in futures.as_completed(res_list)]

    assert raw_response_list == [True, True]


def test_default_ssl_context_creation_without_ssl() -> None:
    """Verify _make_ssl_context does not raise when ssl is not available."""
    with mock.patch.object(connector_module, "ssl", None):
        assert connector_module._make_ssl_context(False) is None
        assert connector_module._make_ssl_context(True) is None


def _acquired_connection(
    conn: aiohttp.BaseConnector, proto: ResponseHandler, key: ConnectionKey
) -> Connection:
    conn._acquired.add(proto)
    conn._acquired_per_host[key].add(proto)
    return Connection(conn, key, proto, conn._loop)


async def test_available_connections_with_limit_per_host(
    key: ConnectionKey, other_host_key2: ConnectionKey
) -> None:
    """Verify expected values based on active connections with host limit."""
    conn = aiohttp.BaseConnector(limit=3, limit_per_host=2)
    assert conn._available_connections(key) == 2
    assert conn._available_connections(other_host_key2) == 2
    proto1 = create_mocked_conn()
    connection1 = _acquired_connection(conn, proto1, key)
    assert conn._available_connections(key) == 1
    assert conn._available_connections(other_host_key2) == 2
    proto2 = create_mocked_conn()
    connection2 = _acquired_connection(conn, proto2, key)
    assert conn._available_connections(key) == 0
    assert conn._available_connections(other_host_key2) == 1
    connection1.close()
    assert conn._available_connections(key) == 1
    assert conn._available_connections(other_host_key2) == 2
    connection2.close()
    other_proto1 = create_mocked_conn()
    other_connection1 = _acquired_connection(conn, other_proto1, other_host_key2)
    assert conn._available_connections(key) == 2
    assert conn._available_connections(other_host_key2) == 1
    other_connection1.close()
    assert conn._available_connections(key) == 2
    assert conn._available_connections(other_host_key2) == 2


@pytest.mark.parametrize("limit_per_host", [0, 10])
async def test_available_connections_without_limit_per_host(
    key: ConnectionKey, other_host_key2: ConnectionKey, limit_per_host: int
) -> None:
    """Verify expected values based on active connections with higher host limit."""
    conn = aiohttp.BaseConnector(limit=3, limit_per_host=limit_per_host)
    assert conn._available_connections(key) == 3
    assert conn._available_connections(other_host_key2) == 3
    proto1 = create_mocked_conn()
    connection1 = _acquired_connection(conn, proto1, key)
    assert conn._available_connections(key) == 2
    assert conn._available_connections(other_host_key2) == 2
    proto2 = create_mocked_conn()
    connection2 = _acquired_connection(conn, proto2, key)
    assert conn._available_connections(key) == 1
    assert conn._available_connections(other_host_key2) == 1
    connection1.close()
    assert conn._available_connections(key) == 2
    assert conn._available_connections(other_host_key2) == 2
    connection2.close()
    other_proto1 = create_mocked_conn()
    other_connection1 = _acquired_connection(conn, other_proto1, other_host_key2)
    assert conn._available_connections(key) == 2
    assert conn._available_connections(other_host_key2) == 2
    other_connection1.close()
    assert conn._available_connections(key) == 3
    assert conn._available_connections(other_host_key2) == 3


async def test_available_connections_no_limits(
    key: ConnectionKey, other_host_key2: ConnectionKey
) -> None:
    """Verify expected values based on active connections with no limits."""
    # No limits is a special case where available connections should always be 1.
    conn = aiohttp.BaseConnector(limit=0, limit_per_host=0)
    assert conn._available_connections(key) == 1
    assert conn._available_connections(other_host_key2) == 1
    proto1 = create_mocked_conn()
    connection1 = _acquired_connection(conn, proto1, key)
    assert conn._available_connections(key) == 1
    assert conn._available_connections(other_host_key2) == 1
    connection1.close()
    assert conn._available_connections(key) == 1
    assert conn._available_connections(other_host_key2) == 1
