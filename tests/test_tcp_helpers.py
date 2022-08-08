import socket
from unittest import mock

import pytest

from aiohttp.tcp_helpers import tcp_nodelay

has_ipv6 = socket.has_ipv6
if has_ipv6:
    # The socket.has_ipv6 flag may be True if Python was built with IPv6
    # support, but the target system still may not have it.
    # So let's ensure that we really have IPv6 support.
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM):
            pass
    except OSError:
        has_ipv6 = False


# nodelay


def test_tcp_nodelay_exception() -> None:
    transport = mock.Mock()
    s = mock.Mock()
    s.setsockopt = mock.Mock()
    s.family = socket.AF_INET
    s.setsockopt.side_effect = OSError
    transport.get_extra_info.return_value = s
    tcp_nodelay(transport, True)
    s.setsockopt.assert_called_with(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)


def test_tcp_nodelay_enable() -> None:
    transport = mock.Mock()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        transport.get_extra_info.return_value = s
        tcp_nodelay(transport, True)
        assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


def test_tcp_nodelay_enable_and_disable() -> None:
    transport = mock.Mock()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        transport.get_extra_info.return_value = s
        tcp_nodelay(transport, True)
        assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
        tcp_nodelay(transport, False)
        assert not s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not has_ipv6, reason="IPv6 is not available")
def test_tcp_nodelay_enable_ipv6() -> None:
    transport = mock.Mock()
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        transport.get_extra_info.return_value = s
        tcp_nodelay(transport, True)
        assert s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="requires unix sockets")
def test_tcp_nodelay_enable_unix() -> None:
    # do not set nodelay for unix socket
    transport = mock.Mock()
    s = mock.Mock(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    tcp_nodelay(transport, True)
    assert not s.setsockopt.called


def test_tcp_nodelay_enable_no_socket() -> None:
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    tcp_nodelay(transport, True)
