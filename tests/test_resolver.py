import pytest
import asyncio
import socket
import ipaddress
from aiohttp.resolver import AsyncResolver, DefaultResolver
from unittest.mock import patch

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
def test_async_resolver_positive_lookup(loop):
    @asyncio.coroutine
    def go():
        with patch('aiodns.DNSResolver.query') as mock_query:
            mock_query.return_value = fake_result(['127.0.0.1'])
            resolver = AsyncResolver(loop=loop)
            real = yield from resolver.resolve('www.python.org')
            ipaddress.ip_address(real[0]['host'])
    loop.run_until_complete(go())


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
def test_async_resolver_multiple_replies(loop):
    @asyncio.coroutine
    def go():
        with patch('aiodns.DNSResolver.query') as mock_query:
            ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
            mock_query.return_value = fake_result(ips)
            resolver = AsyncResolver(loop=loop)
            real = yield from resolver.resolve('www.google.com')
            ips = [ipaddress.ip_address(x['host']) for x in real]
            assert len(ips) > 3, "Expecting multiple addresses"
    loop.run_until_complete(go())


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
def test_async_negative_lookup(loop):
    @asyncio.coroutine
    def go():
        with patch('aiodns.DNSResolver.query') as mock_query:
            mock_query.side_effect = aiodns.error.DNSError()
            resolver = AsyncResolver(loop=loop)
            try:
                yield from resolver.resolve('doesnotexist.bla')
                assert False, "Expecting aiodns.error.DNSError"
            except aiodns.error.DNSError:
                pass

    loop.run_until_complete(go())


def test_default_resolver_positive_lookup(loop):
    @asyncio.coroutine
    def go():
        loop.getaddrinfo = fake_addrinfo(["127.0.0.1"])
        resolver = DefaultResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org')
        ipaddress.ip_address(real[0]['host'])

    loop.run_until_complete(go())


def test_default_resolver_multiple_replies(loop):
    @asyncio.coroutine
    def go():
        ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
        loop.getaddrinfo = fake_addrinfo(ips)
        resolver = DefaultResolver(loop=loop)
        real = yield from resolver.resolve('www.google.com')
        ips = [ipaddress.ip_address(x['host']) for x in real]
        assert len(ips) > 3, "Expecting multiple addresses"
    loop.run_until_complete(go())


def test_default_negative_lookup(loop):
    @asyncio.coroutine
    def go():
        ips = []
        loop.getaddrinfo = fake_addrinfo(ips)
        resolver = DefaultResolver(loop=loop)
        try:
            yield from resolver.resolve('doesnotexist.bla')
            assert False, "Expecting socket.gaierror"
        except socket.gaierror:
            pass

    loop.run_until_complete(go())
