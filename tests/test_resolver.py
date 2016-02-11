import pytest
import asyncio
import socket
import ipaddress
import aiodns
from aiohttp.resolver import AsyncResolver, DefaultResolver


@pytest.fixture
def loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(None)
    return loop


def test_async_resolver_positive_lookup(loop):
    @asyncio.coroutine
    def go():
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org')
        ipaddress.ip_address(real[0]['host'])

    loop.run_until_complete(go())

def test_async_resolver_multiple_replies(loop):
    @asyncio.coroutine
    def go():
        resolver = AsyncResolver(loop=loop)
        real = yield from resolver.resolve('www.google.com')
        ips = [ipaddress.ip_address(x['host']) for x in real]
        assert len(ips) > 3, "Expecting multiple addresses"
    loop.run_until_complete(go())

def test_async_negative_lookup(loop):
    @asyncio.coroutine
    def go():
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
        resolver = DefaultResolver(loop=loop)
        real = yield from resolver.resolve('www.python.org')
        ipaddress.ip_address(real[0]['host'])

    loop.run_until_complete(go())

def test_default_resolver_multiple_replies(loop):
    @asyncio.coroutine
    def go():
        resolver = DefaultResolver(loop=loop)
        real = yield from resolver.resolve('www.google.com')
        ips = [ipaddress.ip_address(x['host']) for x in real]
        assert len(ips) > 3, "Expecting multiple addresses"
    loop.run_until_complete(go())

def test_default_negative_lookup(loop):
    @asyncio.coroutine
    def go():
        resolver = DefaultResolver(loop=loop)
        try:
            yield from resolver.resolve('doesnotexist.bla')
            assert False, "Expecting socket.gaierror"
        except socket.gaierror:
            pass

    loop.run_until_complete(go())
