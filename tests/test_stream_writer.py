import socket
from unittest import mock

import pytest

from aiohttp.parsers import CORK, StreamWriter

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

def test_nodelay_default(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    assert not writer.tcp_nodelay
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_set_nodelay_no_change(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(False)
    assert not writer.tcp_nodelay
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_set_nodelay_exception(loop):
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = (socket.AF_INET,)
    s.setsockopt.side_effect = OSError
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(True)
    assert not writer.tcp_nodelay


def test_set_nodelay_enable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_set_nodelay_enable_and_disable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(True)
    writer.set_tcp_nodelay(False)
    assert not writer.tcp_nodelay
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
def test_set_nodelay_enable_ipv6(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
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
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(True)
    assert not writer.tcp_nodelay


def test_set_nodelay_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
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
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_no_change(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(False)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(True)
    assert writer.tcp_cork
    assert s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_and_disable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
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
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
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
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(True)
    assert not writer.tcp_cork


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(True)
    assert not writer.tcp_cork
    assert writer._socket is None


def test_set_cork_exception(loop):
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = (socket.AF_INET,)
    s.setsockopt.side_effect = OSError
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(True)
    assert not writer.tcp_cork


# cork and nodelay interference

@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_enabling_cork_disables_nodelay(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
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
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(True)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
    assert not writer.tcp_cork
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)
