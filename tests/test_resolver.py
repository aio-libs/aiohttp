import asyncio
import ipaddress
import socket
from unittest.mock import Mock

import pytest

from aiohttp.resolver import AsyncResolver, DefaultResolver, ThreadedResolver


try:
    import aiodns
    gethostbyname = hasattr(aiodns.DNSResolver, 'gethostbyname')
except ImportError:
    aiodns = None
    gethostbyname = False


class FakeResult:
    def __init__(self, addresses):
        self.addresses = addresses


class FakeQueryResult:
    def __init__(self, host):
        self.host = host


async def fake_result(addresses):
    return FakeResult(addresses=tuple(addresses))


async def fake_query_result(result):
    return [FakeQueryResult(host=h) for h in result]


def fake_addrinfo(hosts):
    async def fake(*args, **kwargs):
        if not hosts:
            raise socket.gaierror

        return list([(socket.AF_INET, None, 0, None, [h, 0])
                     for h in hosts])

    return fake


async def test_async_resolver_positive_lookup(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    impl.gethostbyname.return_value = fake_result(['127.0.0.1'])
    resolver._resolver = impl
    real = await resolver.resolve('www.python.org')
    ipaddress.ip_address(real[0]['host'])
    impl.gethostbyname.assert_called_with('www.python.org',
                                          socket.AF_INET)


async def test_async_resolver_query_positive_lookup(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    del impl.gethostbyname
    impl.query.return_value = fake_query_result(['127.0.0.1'])
    resolver._resolver = impl
    real = await resolver.resolve('www.python.org')
    ipaddress.ip_address(real[0]['host'])
    impl.query.assert_called_with('www.python.org', 'A')


async def test_async_resolver_multiple_replies(loop):
    resolver = AsyncResolver(loop=loop)
    ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
    impl = Mock()
    impl.gethostbyname.return_value = fake_result(ips)
    resolver._resolver = impl
    real = await resolver.resolve('www.google.com')
    ips2 = [ipaddress.ip_address(x['host']) for x in real]
    assert len(ips2) > 3, "Expecting multiple addresses"


async def test_async_resolver_query_multiple_replies(loop):
    ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    del impl.gethostbyname
    impl.query.return_value = fake_query_result(ips)
    resolver._resolver = impl
    real = await resolver.resolve('www.google.com')
    ips2 = [ipaddress.ip_address(x['host']) for x in real]
    assert len(ips2) > 3, "Expecting multiple addresses"


async def test_async_resolver_negative_lookup(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    impl.gethostbyname.side_effect = aiodns.error.DNSError()
    resolver._resolver = impl
    with pytest.raises(OSError):
        await resolver.resolve('doesnotexist.bla')


async def test_async_resolver_query_negative_lookup(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    del impl.gethostbyname
    impl.query.side_effect = aiodns.error.DNSError()
    resolver._resolver = impl
    with pytest.raises(OSError):
        await resolver.resolve('doesnotexist.bla')


async def test_async_resolver_no_hosts_in_query(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    del impl.gethostbyname
    impl.query.return_value = fake_query_result([])
    resolver._resolver = impl
    with pytest.raises(OSError):
        await resolver.resolve('doesnotexist.bla')


async def test_async_resolver_no_hosts_in_gethostbyname(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    impl.gethostbyname.return_value = fake_result([])
    resolver._resolver = impl
    with pytest.raises(OSError):
        await resolver.resolve('doesnotexist.bla')


async def test_threaded_resolver_positive_lookup():
    loop = Mock()
    loop.getaddrinfo = fake_addrinfo(["127.0.0.1"])
    resolver = ThreadedResolver(loop=loop)
    real = await resolver.resolve('www.python.org')
    ipaddress.ip_address(real[0]['host'])


async def test_threaded_resolver_multiple_replies():
    loop = Mock()
    ips = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4']
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver(loop=loop)
    real = await resolver.resolve('www.google.com')
    ips = [ipaddress.ip_address(x['host']) for x in real]
    assert len(ips) > 3, "Expecting multiple addresses"


async def test_threaded_negative_lookup():
    loop = Mock()
    ips = []
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver(loop=loop)
    with pytest.raises(socket.gaierror):
        await resolver.resolve('doesnotexist.bla')


async def test_close_for_threaded_resolver(loop):
    resolver = ThreadedResolver(loop=loop)
    await resolver.close()


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
async def test_close_for_async_resolver(loop):
    resolver = AsyncResolver(loop=loop)
    await resolver.close()


def test_default_loop_for_threaded_resolver(loop):
    asyncio.set_event_loop(loop)
    resolver = ThreadedResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
def test_default_loop_for_async_resolver(loop):
    asyncio.set_event_loop(loop)
    resolver = AsyncResolver()
    assert resolver._loop is loop


async def test_async_resolver_ipv6_positive_lookup(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    impl.gethostbyname.return_value = fake_result(['::1'])
    resolver._resolver = impl
    real = await resolver.resolve('www.python.org',
                                  family=socket.AF_INET6)
    ipaddress.ip_address(real[0]['host'])
    impl.gethostbyname.assert_called_with('www.python.org',
                                          socket.AF_INET6)


async def test_async_resolver_query_ipv6_positive_lookup(loop):
    resolver = AsyncResolver(loop=loop)
    impl = Mock()
    del impl.gethostbyname
    impl.query.return_value = fake_query_result(['::1'])
    resolver._resolver = impl
    real = await resolver.resolve('www.python.org',
                                  family=socket.AF_INET6)
    ipaddress.ip_address(real[0]['host'])
    impl.query.assert_called_with('www.python.org', 'AAAA')


def test_async_resolver_aiodns_not_present(loop, monkeypatch):
    monkeypatch.setattr("aiohttp.resolver.aiodns", None)
    with pytest.raises(RuntimeError):
        AsyncResolver(loop=loop)


def test_default_resolver():
    # if gethostbyname:
    #     assert DefaultResolver is AsyncResolver
    # else:
    #     assert DefaultResolver is ThreadedResolver
    assert DefaultResolver is ThreadedResolver
