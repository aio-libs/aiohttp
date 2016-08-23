import asyncio
import ipaddress
import socket
from unittest.mock import patch

import pytest

from aiohttp.resolver import AsyncResolver, DefaultResolver

try:
    import aiodns
except ImportError:
    aiodns = None


class FakeResult:
    def __init__(self, host):
        self.host = host


@asyncio.coroutine
def fake_result(result):
    return [FakeResult(host=h)
            for h in result]


def fake_addrinfo(hosts):
    @asyncio.coroutine
    def fake(*args, **kwargs):
        if not hosts:
            raise socket.gaierror

        return list([(None, None, None, None, [h, 0])
                     for h in hosts])

    return fake


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_positive_lookup(loop):
    with patch('aiodns.DNSResolver.query') as mock_query:
        mock_query.return_value = fake_result(['127.0.0.1'])
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org')
        ipaddress.ip_address(real[0]['host'])
        mock_query.assert_called_with('www.python.org', 'A')


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_multiple_replies(loop):
    with patch('aiodns.DNSResolver.query') as mock_query:
        ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
        mock_query.return_value = fake_result(ips)
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.google.com')
        ips = [ipaddress.ip_address(x['host']) for x in real]
        assert len(ips) > 3, "Expecting multiple addresses"


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_negative_lookup(loop):
    with patch('aiodns.DNSResolver.query') as mock_query:
        mock_query.side_effect = aiodns.error.DNSError()
        resolver = AsyncResolver(loop=loop)
        with pytest.raises(aiodns.error.DNSError):
            yield from resolver.resolve('doesnotexist.bla')


@asyncio.coroutine
def test_default_resolver_positive_lookup(loop):
    loop.getaddrinfo = fake_addrinfo(["127.0.0.1"])
    resolver = DefaultResolver(loop=loop)
    real = yield from resolver.resolve('www.python.org')
    ipaddress.ip_address(real[0]['host'])


@asyncio.coroutine
def test_default_resolver_multiple_replies(loop):
    ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = DefaultResolver(loop=loop)
    real = yield from resolver.resolve('www.google.com')
    ips = [ipaddress.ip_address(x['host']) for x in real]
    assert len(ips) > 3, "Expecting multiple addresses"


@asyncio.coroutine
def test_default_negative_lookup(loop):
    ips = []
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = DefaultResolver(loop=loop)
    with pytest.raises(socket.gaierror):
        yield from resolver.resolve('doesnotexist.bla')


@asyncio.coroutine
def test_close_for_default_resolver(loop):
    resolver = DefaultResolver(loop=loop)
    yield from resolver.close()


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_close_for_async_resolver(loop):
    resolver = AsyncResolver(loop=loop)
    yield from resolver.close()


def test_default_loop_for_default_resolver(loop):
    asyncio.set_event_loop(loop)
    resolver = DefaultResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
def test_default_loop_for_async_resolver(loop):
    asyncio.set_event_loop(loop)
    resolver = AsyncResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_ipv6_positive_lookup(loop):
    with patch('aiodns.DNSResolver.query') as mock_query:
        mock_query.return_value = fake_result(['::1'])
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org',
                                           family=socket.AF_INET6)
        ipaddress.ip_address(real[0]['host'])
        mock_query.assert_called_with('www.python.org', 'AAAA')


def test_async_resolver_aiodns_not_present(loop, monkeypatch):
    monkeypatch.setattr("aiohttp.resolver.aiodns", None)
    with pytest.raises(RuntimeError):
        AsyncResolver(loop=loop)
