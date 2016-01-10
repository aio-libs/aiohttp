import pytest
import socket
from aiohttp.parsers import StreamWriter, CORK
from unittest import mock


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
    transport = mock.Mock()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    transport.get_extra_info.return_value = s
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay


def test_set_nodelay_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_nodelay(True)
    assert writer.tcp_nodelay
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
    assert writer.tcp_cork


@pytest.mark.skipif(CORK is None, reason="TCP_CORK or TCP_NOPUSH required")
def test_set_cork_enable_no_socket(loop):
    transport = mock.Mock()
    transport.get_extra_info.return_value = None
    proto = mock.Mock()
    reader = mock.Mock()
    writer = StreamWriter(transport, proto, reader, loop)
    writer.set_tcp_cork(True)
    assert writer.tcp_cork
    assert writer._socket is None


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
