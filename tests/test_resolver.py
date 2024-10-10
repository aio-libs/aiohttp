import asyncio
import ipaddress
import socket
from ipaddress import ip_address
from typing import Any, Awaitable, Callable, Collection, List, NamedTuple, Tuple, Union
from unittest.mock import Mock, create_autospec, patch

import pytest

from aiohttp.resolver import (
    _NAME_SOCKET_FLAGS,
    AsyncResolver,
    DefaultResolver,
    ThreadedResolver,
)

try:
    import aiodns

    getaddrinfo: Any = hasattr(aiodns.DNSResolver, "getaddrinfo")
except ImportError:
    aiodns = None  # type: ignore[assignment]
    getaddrinfo = False


class FakeAIODNSAddrInfoNode(NamedTuple):

    family: int
    addr: Union[Tuple[bytes, int], Tuple[bytes, int, int, int]]


class FakeAIODNSAddrInfoIPv4Result:
    def __init__(self, hosts: Collection[str]) -> None:
        self.nodes = [
            FakeAIODNSAddrInfoNode(socket.AF_INET, (h.encode(), 0)) for h in hosts
        ]


class FakeAIODNSAddrInfoIPv6Result:
    def __init__(self, hosts: Collection[str]) -> None:
        self.nodes = [
            FakeAIODNSAddrInfoNode(
                socket.AF_INET6,
                (h.encode(), 0, 0, 3 if ip_address(h).is_link_local else 0),
            )
            for h in hosts
        ]


class FakeAIODNSNameInfoIPv6Result:
    def __init__(self, host: str) -> None:
        self.node = host
        self.service = None


class FakeQueryResult:
    host: Any

    def __init__(self, host: Any) -> None:
        self.host = host


async def fake_aiodns_getaddrinfo_ipv4_result(
    hosts: Collection[str],
) -> FakeAIODNSAddrInfoIPv4Result:
    return FakeAIODNSAddrInfoIPv4Result(hosts=hosts)


async def fake_aiodns_getaddrinfo_ipv6_result(
    hosts: Collection[str],
) -> FakeAIODNSAddrInfoIPv6Result:
    return FakeAIODNSAddrInfoIPv6Result(hosts=hosts)


async def fake_aiodns_getnameinfo_ipv6_result(
    host: str,
) -> FakeAIODNSNameInfoIPv6Result:
    return FakeAIODNSNameInfoIPv6Result(host)


async def fake_query_result(result: Any) -> List[FakeQueryResult]:
    return [FakeQueryResult(host=h) for h in result]


def fake_addrinfo(hosts: Collection[str]) -> Callable[..., Awaitable[Any]]:
    async def fake(*args: Any, **kwargs: Any) -> List[Any]:
        if not hosts:
            raise socket.gaierror

        return [(socket.AF_INET, None, socket.SOCK_STREAM, None, [h, 0]) for h in hosts]

    return fake


def fake_ipv6_addrinfo(hosts: Collection[str]) -> Callable[..., Awaitable[Any]]:
    async def fake(*args: Any, **kwargs: Any) -> List[Any]:
        if not hosts:
            raise socket.gaierror

        return [
            (
                socket.AF_INET6,
                None,
                socket.SOCK_STREAM,
                None,
                (h, 0, 0, 3 if ip_address(h).is_link_local else 0),
            )
            for h in hosts
        ]

    return fake


def fake_ipv6_nameinfo(host: str) -> Callable[..., Awaitable[Any]]:
    async def fake(*args: Any, **kwargs: Any) -> Tuple[str, int]:
        return host, 0

    return fake


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_positive_ipv4_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv4_result(
            ["127.0.0.1"]
        )
        resolver = AsyncResolver()
        real = await resolver.resolve("www.python.org")
        ipaddress.ip_address(real[0]["host"])
        mock().getaddrinfo.assert_called_with(
            "www.python.org",
            family=socket.AF_INET,
            flags=socket.AI_ADDRCONFIG,
            port=0,
            type=socket.SOCK_STREAM,
        )


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_positive_link_local_ipv6_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv6_result(
            ["fe80::1"]
        )
        mock().getnameinfo.return_value = fake_aiodns_getnameinfo_ipv6_result(
            "fe80::1%eth0"
        )
        resolver = AsyncResolver()
        real = await resolver.resolve("www.python.org")
        ipaddress.ip_address(real[0]["host"])
        mock().getaddrinfo.assert_called_with(
            "www.python.org",
            family=socket.AF_INET,
            flags=socket.AI_ADDRCONFIG,
            port=0,
            type=socket.SOCK_STREAM,
        )
        mock().getnameinfo.assert_called_with(("fe80::1", 0, 0, 3), _NAME_SOCKET_FLAGS)


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_multiple_replies(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        ips = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv4_result(ips)
        resolver = AsyncResolver()
        real = await resolver.resolve("www.google.com")
        ipaddrs = [ipaddress.ip_address(x["host"]) for x in real]
        assert len(ipaddrs) > 3, "Expecting multiple addresses"


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_negative_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.side_effect = aiodns.error.DNSError()
        resolver = AsyncResolver()
        with pytest.raises(OSError):
            await resolver.resolve("doesnotexist.bla")


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_no_hosts_in_getaddrinfo(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv4_result([])
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


async def test_threaded_resolver_positive_ipv6_link_local_lookup() -> None:
    loop = Mock()
    loop.getaddrinfo = fake_ipv6_addrinfo(["fe80::1"])
    loop.getnameinfo = fake_ipv6_nameinfo("fe80::1%eth0")

    # Mock the fake function that was returned by helper functions
    loop.getaddrinfo = create_autospec(loop.getaddrinfo)
    loop.getnameinfo = create_autospec(loop.getnameinfo)

    # Set the correct return values for mock functions
    loop.getaddrinfo.return_value = await fake_ipv6_addrinfo(["fe80::1"])()
    loop.getnameinfo.return_value = await fake_ipv6_nameinfo("fe80::1%eth0")()

    resolver = ThreadedResolver()
    resolver._loop = loop
    real = await resolver.resolve("www.python.org")
    assert real[0]["hostname"] == "www.python.org"
    ipaddress.ip_address(real[0]["host"])

    loop.getaddrinfo.assert_called_with(
        "www.python.org",
        0,
        type=socket.SOCK_STREAM,
        family=socket.AF_INET,
        flags=socket.AI_ADDRCONFIG,
    )

    loop.getnameinfo.assert_called_with(("fe80::1", 0, 0, 3), _NAME_SOCKET_FLAGS)


async def test_threaded_resolver_multiple_replies() -> None:
    loop = Mock()
    ips = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver()
    resolver._loop = loop
    real = await resolver.resolve("www.google.com")
    ipaddrs = [ipaddress.ip_address(x["host"]) for x in real]
    assert len(ipaddrs) > 3, "Expecting multiple addresses"


async def test_threaded_negative_lookup() -> None:
    loop = Mock()
    ips: List[Any] = []
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver()
    resolver._loop = loop
    with pytest.raises(socket.gaierror):
        await resolver.resolve("doesnotexist.bla")


async def test_threaded_negative_ipv6_lookup() -> None:
    loop = Mock()
    ips: List[Any] = []
    loop.getaddrinfo = fake_ipv6_addrinfo(ips)
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


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_ipv6_positive_lookup(loop: Any) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv6_result(["::1"])
        resolver = AsyncResolver()
        real = await resolver.resolve("www.python.org")
        ipaddress.ip_address(real[0]["host"])
        mock().getaddrinfo.assert_called_with(
            "www.python.org",
            family=socket.AF_INET,
            flags=socket.AI_ADDRCONFIG,
            port=0,
            type=socket.SOCK_STREAM,
        )


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_async_resolver_error_messages_passed(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Ensure error messages are passed through from aiodns."""
    with patch("aiodns.DNSResolver", autospec=True, spec_set=True) as mock:
        mock().getaddrinfo.side_effect = aiodns.error.DNSError(1, "Test error message")
        resolver = AsyncResolver()
        with pytest.raises(OSError, match="Test error message") as excinfo:
            await resolver.resolve("x.org")

        assert excinfo.value.strerror == "Test error message"


async def test_async_resolver_aiodns_not_present(loop: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr("aiohttp.resolver.aiodns", None)
    with pytest.raises(RuntimeError):
        AsyncResolver()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
def test_aio_dns_is_default() -> None:
    assert DefaultResolver is AsyncResolver


@pytest.mark.skipif(getaddrinfo, reason="aiodns <3.2.0 required")
def test_threaded_resolver_is_default() -> None:
    assert DefaultResolver is ThreadedResolver
