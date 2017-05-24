import asyncio
import socket
from unittest import mock

import pytest

from aiohttp.http_writer import CORK, PayloadWriter, StreamWriter


has_ipv6 = socket.has_ipv6
if has_ipv6:
    # The socket.has_ipv6 flag may be True if Python was built with IPv6
    # support, but the target system still may not have it.
    # So let's ensure that we really have IPv6 support.
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        has_ipv6 = False


# nodelay

def test_nodelay_and_cork_default(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    assert not writer.tcp_nodelay
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_set_nodelay_no_change(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(False)
    assert not writer.tcp_nodelay
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_set_nodelay_exception(loop):
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = socket.AF_INET
    s.setsockopt.side_effect = OSError
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    assert not writer.tcp_nodelay


def test_set_nodelay_enable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_set_nodelay_enable_and_disable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    writer.set_tcp_nodelay(False)
    assert not writer.tcp_nodelay
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_nodelay_and_cork(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
    assert not writer.tcp_cork
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
def test_set_nodelay_enable_ipv6(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="requires unix sockets")
def test_set_nodelay_enable_unix(loop):
    # do not set nodelay for unix socket
    transport = mock.Mock()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    assert not writer.tcp_nodelay


def test_set_nodelay_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    assert not writer.tcp_nodelay
    assert writer._socket is None


# cork

@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_cork_default(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_no_change(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(False)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    assert writer.tcp_cork
    assert s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_and_disable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    writer.set_tcp_cork(False)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_ipv6(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    assert writer.tcp_cork
    assert s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="requires unix sockets")
@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_unix(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    assert not writer.tcp_cork


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    assert not writer.tcp_cork
    assert writer._socket is None


def test_set_cork_exception(loop):
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = socket.AF_INET
    s.setsockopt.side_effect = OSError
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    assert not writer.tcp_cork


# cork and nodelay interference

@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_enabling_cork_disables_nodelay(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_nodelay(True)
    writer.set_tcp_cork(True)
    assert not writer.tcp_nodelay
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
    assert writer.tcp_cork
    assert s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_enabling_nodelay_disables_cork(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    writer = StreamWriter(proto, transport, loop)
    writer.set_tcp_cork(True)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


# payload writers management

def test_acquire(loop):
    transport = mock.Mock()
    stream = StreamWriter(mock.Mock(), transport, loop)
    assert stream.available

    payload = PayloadWriter(stream, loop)
    assert not stream.available
    assert payload._transport is transport

    payload2 = PayloadWriter(stream, loop)
    assert payload2._transport is None
    assert payload2 in stream._waiters


def test_acquire2(loop):
    transport = mock.Mock()
    stream = StreamWriter(mock.Mock(), transport, loop)

    payload = PayloadWriter(stream, loop)
    stream.release()
    assert stream.available

    stream.acquire(payload)
    assert not stream.available
    assert payload._transport is transport


def test_release(loop):
    transport = mock.Mock()
    stream = StreamWriter(mock.Mock(), transport, loop)
    stream.available = False

    writer = mock.Mock()

    stream.acquire(writer)
    assert not stream.available
    assert not writer.set_transport.called

    stream.release()
    assert not stream.available
    writer.set_transport.assert_called_with(transport)

    stream.release()
    assert stream.available


def test_replace(loop):
    transport = mock.Mock()
    stream = StreamWriter(mock.Mock(), transport, loop)
    stream.available = False

    payload = PayloadWriter(stream, loop)
    assert payload._transport is None
    assert payload in stream._waiters

    payload2 = stream.replace(payload, PayloadWriter)
    assert payload2._transport is None
    assert payload2 in stream._waiters
    assert payload not in stream._waiters

    stream.release()
    assert payload2._transport is transport
    assert not stream._waiters


def test_replace_available(loop):
    transport = mock.Mock()
    stream = StreamWriter(mock.Mock(), transport, loop)

    payload = PayloadWriter(stream, loop, False)
    payload2 = stream.replace(payload, PayloadWriter)
    assert payload2._transport is transport
    assert payload2 not in stream._waiters


@asyncio.coroutine
def test_concurrent_drains(loop):
    # high limit for write buffer is about 4 MB
    PACKET = b'1234567890' * 1024 * 1024

    fut0 = asyncio.Future(loop=loop)
    fut1 = asyncio.Future(loop=loop)
    fut2 = asyncio.Future(loop=loop)
    fut3 = asyncio.Future(loop=loop)

    class Proto(asyncio.streams.FlowControlMixin):
        def connection_made(self, transport):
            super().connection_made(transport)
            self.transport = transport

    @asyncio.coroutine
    def read(reader, writer):
        yield from fut1
        ret = object()
        res = b''
        while ret:
            ret = yield from reader.read()
            res += ret
        assert res == PACKET*3
        fut2.set_result(None)

    server = yield from asyncio.start_server(read, '127.0.0.1', 0, loop=loop)
    port = server.sockets[0].getsockname()[1]

    tr, pr = yield from loop.create_connection(Proto, '127.0.0.1', port)

    stream = StreamWriter(pr, tr, loop)
    tr.set_write_buffer_limits(1, 1)

    started = 0
    finished = 0

    @asyncio.coroutine
    def write():
        nonlocal started, finished
        started += 1
        if started == 3:
            fut0.set_result(None)
        tr.write(PACKET)
        yield from stream.drain()
        finished += 1
        if finished == 3:
            fut3.set_result(None)

    tasks = [loop.create_task(write()) for i in range(3)]

    yield from fut0
    assert started == 3
    assert finished == 0
    fut1.set_result(None)
    yield from fut3
    tr.close()
    yield from fut2
    assert started == 3
    assert finished == 3

    tr.close()

    yield from asyncio.gather(*tasks, loop=loop)
    server.close()
    yield from server.wait_closed()
