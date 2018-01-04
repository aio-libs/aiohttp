import socket
from unittest import mock

import pytest

from aiohttp.tcp_helpers import tcp_nodelay, tcp_cork, CORK


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

def test_tcp_nodelay_exception(loop):
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = socket.AF_INET
    s.setsockopt.side_effect = OSError
    transport.get_extra_info.return_value = s
    assert tcp_nodelay(transport, True) is None
    s.setsockopt.assert_called_with(
        socket.IPPROTO_TCP,
        socket.TCP_NODELAY,
        True
    )


def test_tcp_nodelay_enable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_nodelay(transport, True) is True
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_tcp_nodelay_enable_and_disable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_nodelay(transport, True) is True
    assert tcp_nodelay(transport, False) is False
    assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
def test_tcp_nodelay_enable_ipv6(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_nodelay(transport, True) is True
    assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="requires unix sockets")
def test_tcp_nodelay_enable_unix(loop):
    # do not set nodelay for unix socket
    transport = mock.Mock()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_nodelay(transport, True) is None


def test_tcp_nodelay_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    assert tcp_nodelay(transport, True) is None


# cork


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_tcp_cork_enable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_cork(transport, True) is True
    assert s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_and_disable(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_cork(transport, True) is True
    assert tcp_cork(transport, False) is False
    assert not s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_ipv6(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_cork(transport, True) is True
    assert s.getsockopt(socket.IPPROTO_TCP, CORK)


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'),
                    reason="requires unix sockets")
@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_unix(loop):
    transport = mock.Mock()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    assert tcp_cork(transport, True) is True


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    assert tcp_cork(transport, True) is None


def test_set_cork_exception(loop):
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = socket.AF_INET
    s.setsockopt.side_effect = OSError
    assert tcp_cork(transport, True) is None
