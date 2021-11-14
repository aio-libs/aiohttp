import asyncio
import ipaddress
import socket
from typing import Any, Awaitable, Callable, List
from unittest.mock import Mock, patch

import pytest

from aiohttp.resolver import AsyncResolver, DefaultResolver, ThreadedResolver

try:
    import aiodns

    gethostbyname: Any = hasattr(aiodns.DNSResolver, "gethostbyname")
except ImportError:
    aiodns = None
    gethostbyname = False


class FakeResult:
    addresses: Any

    def __init__(self, addresses: Any) -> None:
        self.addresses = addresses


class FakeQueryResult:
    host: Any

    def __init__(self, host: Any) -> None:
        self.host = host


async def fake_result(addresses: Any) -> FakeResult:
    return FakeResult(addresses=tuple(addresses))


async def fake_query_result(result: Any) -> List[FakeQueryResult]:
    return [FakeQueryResult(host=h) for h in result]


def fake_addrinfo(hosts: Any) -> Callable[..., Awaitable[Any]]:
    async def fake(*args: Any, **kwargs: Any) -> List[Any]:
        if not hosts:
            raise socket.gaierror

        return [(socket.AF_INET, None, socket.SOCK_STREAM, None, [h, 0]) for h in hosts]

    return fake


@pytest.mark.skipif(not gethostbyname, reason="aiodns 1.1 required")
async def test_async_resolver_positive_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().gethostbyname.return_value = fake_result(["127.0.0.1"])
        resolver = AsyncResolver()
        real = await resolver.resolve("www.python.org")
        ipaddress.ip_address(real[0]["host"])
        mock().gethostbyname.assert_called_with("www.python.org", socket.AF_INET)


@pytest.mark.skipif(not gethostbyname, reason="aiodns 1.1 required")
async def test_async_resolver_multiple_replies(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        ips = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
        mock().gethostbyname.return_value = fake_result(ips)
        resolver = AsyncResolver()
        real = await resolver.resolve("www.google.com")
        ips = [ipaddress.ip_address(x["host"]) for x in real]
        assert len(ips) > 3, "Expecting multiple addresses"


@pytest.mark.skipif(not gethostbyname, reason="aiodns 1.1 required")
async def test_async_resolver_negative_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().gethostbyname.side_effect = aiodns.error.DNSError()
        resolver = AsyncResolver()
        with pytest.raises(OSError):
            await resolver.resolve("doesnotexist.bla")


@pytest.mark.skipif(not gethostbyname, reason="aiodns 1.1 required")
async def test_async_resolver_no_hosts_in_gethostbyname(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().gethostbyname.return_value = fake_result([])
        resolver = AsyncResolver()
        with pytest.raises(OSError):
            await resolver.resolve("doesnotexist.bla")


async def test_threaded_resolver_positive_lookup() -> None:
    loop = Mock()
    loop.getaddrinfo = fake_addrinfo(["127.0.0.1"])
    resolver = ThreadedResolver()
    resolver._loop = loop
    real = await resolver.resolve("www.python.org")
    assert real[0]["hostname"] == "www.python.org"
    ipaddress.ip_address(real[0]["host"])


async def test_threaded_resolver_multiple_replies() -> None:
    loop = Mock()
    ips = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver()
    resolver._loop = loop
    real = await resolver.resolve("www.google.com")
    ips = [ipaddress.ip_address(x["host"]) for x in real]
    assert len(ips) > 3, "Expecting multiple addresses"


async def test_threaded_negative_lookup() -> None:
    loop = Mock()
    ips: List[Any] = []
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver()
    resolver._loop = loop
    with pytest.raises(socket.gaierror):
        await resolver.resolve("doesnotexist.bla")


async def test_threaded_negative_lookup_with_unknown_result() -> None:
    loop = Mock()

    # If compile CPython with `--disable-ipv6` option,
    # we will get an (int, bytes) tuple, instead of a Exception.
    async def unknown_addrinfo(*args: Any, **kwargs: Any) -> List[Any]:
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                (10, b"\x01\xbb\x00\x00\x00\x00*\x04NB\x00\x1a\x00\x00"),
            )
        ]

    loop.getaddrinfo = unknown_addrinfo
    resolver = ThreadedResolver()
    resolver._loop = loop
    with patch("socket.has_ipv6", False):
        res = await resolver.resolve("www.python.org")
    assert len(res) == 0


async def test_close_for_threaded_resolver(loop: Any) -> None:
    resolver = ThreadedResolver()
    await resolver.close()


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
async def test_close_for_async_resolver(loop: Any) -> None:
    resolver = AsyncResolver()
    await resolver.close()


async def test_default_loop_for_threaded_resolver(loop: Any) -> None:
    asyncio.set_event_loop(loop)
    resolver = ThreadedResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
async def test_default_loop_for_async_resolver(loop: Any) -> None:
    asyncio.set_event_loop(loop)
    resolver = AsyncResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(not gethostbyname, reason="aiodns 1.1 required")
async def test_async_resolver_ipv6_positive_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().gethostbyname.return_value = fake_result(["::1"])
        resolver = AsyncResolver()
        real = await resolver.resolve("www.python.org", family=socket.AF_INET6)
        ipaddress.ip_address(real[0]["host"])
        mock().gethostbyname.assert_called_with("www.python.org", socket.AF_INET6)


async def test_async_resolver_aiodns_not_present(loop: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr("aiohttp.resolver.aiodns", None)
    with pytest.raises(RuntimeError):
        AsyncResolver()


def test_default_resolver() -> None:
    # if gethostbyname:
    #     assert DefaultResolver is AsyncResolver
    # else:
    #     assert DefaultResolver is ThreadedResolver
    assert DefaultResolver is ThreadedResolver
