import asyncio
import ipaddress
import socket
from unittest.mock import call, patch

import pytest

from aiohttp.resolver import AsyncResolver, DefaultResolver, ThreadedResolver

try:
    import aiodns
except ImportError:
    aiodns = None


class FakeQueryResult:
    def __init__(self, host):
        self.host = host


@asyncio.coroutine
def fake_query_result(result):
    return [FakeQueryResult(host=h)
            for h in result]


def fake_addrinfo(hosts):
    @asyncio.coroutine
    def fake(*args, **kwargs):
        if not hosts:
            raise socket.gaierror

        return list([(None, None, None, None, [h, 0])
                     for h in hosts])

    return fake


@asyncio.coroutine
@pytest.mark.skipif(aiodns is None, reason="aiodns required")
def test_async_resolver_positive_lookup(loop):
    with patch('aiodns.DNSResolver') as mock:
        mock().query.return_value = fake_query_result(['127.0.0.1'])
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org')
        ipaddress.ip_address(real[0]['host'])
        mock().query.assert_called_with('www.python.org', 'A')


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_multiple_replies(loop):
    with patch('aiodns.DNSResolver') as mock:
        ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
        mock().query.return_value = fake_query_result(ips)
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.google.com')
        ips = [ipaddress.ip_address(x['host']) for x in real]
        assert len(ips) > 3, "Expecting multiple addresses"


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_negative_lookup(loop):
    with patch('aiodns.DNSResolver') as mock:
        mock().query.side_effect = aiodns.error.DNSError()
        resolver = AsyncResolver(loop=loop)
        with pytest.raises(aiodns.error.DNSError):
            yield from resolver.resolve('doesnotexist.bla')


@asyncio.coroutine
def test_threaded_resolver_positive_lookup(loop):
    loop.getaddrinfo = fake_addrinfo(["127.0.0.1"])
    resolver = ThreadedResolver(loop=loop)
    real = yield from resolver.resolve('www.python.org')
    ipaddress.ip_address(real[0]['host'])


@asyncio.coroutine
def test_threaded_resolver_multiple_replies(loop):
    ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver(loop=loop)
    real = yield from resolver.resolve('www.google.com')
    ips = [ipaddress.ip_address(x['host']) for x in real]
    assert len(ips) > 3, "Expecting multiple addresses"


@asyncio.coroutine
def test_threaded_negative_lookup(loop):
    ips = []
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver(loop=loop)
    with pytest.raises(socket.gaierror):
        yield from resolver.resolve('doesnotexist.bla')


@asyncio.coroutine
def test_close_for_threaded_resolver(loop):
    resolver = ThreadedResolver(loop=loop)
    yield from resolver.close()


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_close_for_async_resolver(loop):
    resolver = AsyncResolver(loop=loop)
    yield from resolver.close()


def test_default_loop_for_threaded_resolver(loop):
    asyncio.set_event_loop(loop)
    resolver = ThreadedResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
def test_default_loop_for_async_resolver(loop):
    asyncio.set_event_loop(loop)
    resolver = AsyncResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_ipv6_positive_lookup(loop):
    with patch('aiodns.DNSResolver') as mock:
        mock().query.return_value = fake_query_result(['::1'])
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org',
                                           family=socket.AF_INET6)
        ipaddress.ip_address(real[0]['host'])
        mock().query.assert_called_with('www.python.org', 'AAAA')


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_family_unspec_positive_lookup(loop):
    with patch('aiodns.DNSResolver') as mock:
        mock().query.return_value = fake_query_result(['127.0.0.1', '::1'])
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org',
                                           family=socket.AF_UNSPEC)
        ipaddress.ip_address(real[0]['host'])
        ipaddress.ip_address(real[1]['host'])
        calls = [call('www.python.org', 'A'), call('www.python.org', 'AAAA')]
        mock().query.assert_has_calls(calls, any_order=True)


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_ipv4_only_positive_lookup(loop):

    def _side_effect(*args, **kwargs):
        if args[1] == 'A':
            return fake_query_result(['127.0.0.1'])
        else:
            raise aiodns.error.DNSError()

    with patch('aiodns.DNSResolver') as mock:
        mock().query.side_effect = _side_effect
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('localhost',
                                           family=socket.AF_UNSPEC)
        ipaddress.ip_address(real[0]['host'])
        assert len(real) == 1, "Bad resolve, IPv4 and IPv6"


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@asyncio.coroutine
def test_async_resolver_ipv6_only_positive_lookup(loop):

    def _side_effect(*args, **kwargs):
        if args[1] == 'A':
            raise aiodns.error.DNSError()
        else:
            return fake_query_result(['::1'])

    with patch('aiodns.DNSResolver.query') as mock:
        mock.side_effect = _side_effect
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('localhost',
                                           family=socket.AF_UNSPEC)
        ipaddress.ip_address(real[0]['host'])
        assert len(real) == 1, "Bad resolve, IPv4 and IPv6"


def test_async_resolver_aiodns_not_present(loop, monkeypatch):
    monkeypatch.setattr("aiohttp.resolver.aiodns", None)
    with pytest.raises(RuntimeError):
        AsyncResolver(loop=loop)


def test_default_resolver():
    if aiodns:
        assert DefaultResolver is AsyncResolver
    else:
        assert DefaultResolver is ThreadedResolver
