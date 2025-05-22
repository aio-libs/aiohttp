import asyncio
import gc
import ipaddress
import socket
from collections.abc import Generator
from ipaddress import ip_address
from typing import (
    Any,
    Awaitable,
    Callable,
    Collection,
    Iterable,
    List,
    NamedTuple,
    Tuple,
    Union,
)
from unittest.mock import Mock, create_autospec, patch

import pytest

from aiohttp.resolver import (
    _NAME_SOCKET_FLAGS,
    AsyncResolver,
    DefaultResolver,
    ThreadedResolver,
    _DNSResolverManager,
)

try:
    import aiodns

    getaddrinfo = hasattr(aiodns.DNSResolver, "getaddrinfo")
except ImportError:
    aiodns = None  # type: ignore[assignment]
    getaddrinfo = False

_AddrInfo4 = List[
    Tuple[socket.AddressFamily, None, socket.SocketKind, None, Tuple[str, int]]
]
_AddrInfo6 = List[
    Tuple[
        socket.AddressFamily, None, socket.SocketKind, None, Tuple[str, int, int, int]
    ]
]
_UnknownAddrInfo = List[
    Tuple[socket.AddressFamily, socket.SocketKind, int, str, Tuple[int, bytes]]
]


@pytest.fixture()
def check_no_lingering_resolvers() -> Generator[None, None, None]:
    """Verify no resolvers remain after the test.

    This fixture should be used in any test that creates instances of
    AsyncResolver or directly uses _DNSResolverManager.
    """
    manager = _DNSResolverManager()
    before = len(manager._loop_data)
    yield
    after = len(manager._loop_data)
    if after > before:  # pragma: no branch
        # Force garbage collection to ensure weak references are updated
        gc.collect()  # pragma: no cover
        after = len(manager._loop_data)  # pragma: no cover
        if after > before:  # pragma: no cover
            pytest.fail(  # pragma: no cover
                f"Lingering resolvers found: {(after - before)} "
                "new AsyncResolver instances were not properly closed."
            )


@pytest.fixture()
def dns_resolver_manager() -> Generator[_DNSResolverManager, None, None]:
    """Create a fresh _DNSResolverManager instance for testing.

    Saves and restores the singleton state to avoid affecting other tests.
    """
    # Save the original instance
    original_instance = _DNSResolverManager._instance

    # Reset the singleton
    _DNSResolverManager._instance = None

    # Create and yield a fresh instance
    try:
        yield _DNSResolverManager()
    finally:
        # Clean up and restore the original instance
        _DNSResolverManager._instance = original_instance


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
    def __init__(self, host: str) -> None:
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


async def fake_query_result(result: Iterable[str]) -> List[FakeQueryResult]:
    return [FakeQueryResult(host=h) for h in result]


def fake_addrinfo(hosts: Collection[str]) -> Callable[..., Awaitable[_AddrInfo4]]:
    async def fake(*args: Any, **kwargs: Any) -> _AddrInfo4:
        if not hosts:
            raise socket.gaierror

        return [(socket.AF_INET, None, socket.SOCK_STREAM, None, (h, 0)) for h in hosts]

    return fake


def fake_ipv6_addrinfo(hosts: Collection[str]) -> Callable[..., Awaitable[_AddrInfo6]]:
    async def fake(*args: Any, **kwargs: Any) -> _AddrInfo6:
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


def fake_ipv6_nameinfo(host: str) -> Callable[..., Awaitable[Tuple[str, int]]]:
    async def fake(*args: Any, **kwargs: Any) -> Tuple[str, int]:
        return host, 0

    return fake


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_positive_ipv4_lookup(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
        await resolver.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_positive_link_local_ipv6_lookup(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
        await resolver.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_multiple_replies(loop: asyncio.AbstractEventLoop) -> None:
    with patch("aiodns.DNSResolver") as mock:
        ips = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv4_result(ips)
        resolver = AsyncResolver()
        real = await resolver.resolve("www.google.com")
        ipaddrs = [ipaddress.ip_address(x["host"]) for x in real]
        assert len(ipaddrs) > 3, "Expecting multiple addresses"
        await resolver.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_negative_lookup(loop: asyncio.AbstractEventLoop) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.side_effect = aiodns.error.DNSError()
        resolver = AsyncResolver()
        with pytest.raises(OSError):
            await resolver.resolve("doesnotexist.bla")
        await resolver.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_no_hosts_in_getaddrinfo(
    loop: asyncio.AbstractEventLoop,
) -> None:
    with patch("aiodns.DNSResolver") as mock:
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv4_result([])
        resolver = AsyncResolver()
        with pytest.raises(OSError):
            await resolver.resolve("doesnotexist.bla")
        await resolver.close()


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
    ips: List[str] = []
    loop.getaddrinfo = fake_addrinfo(ips)
    resolver = ThreadedResolver()
    resolver._loop = loop
    with pytest.raises(socket.gaierror):
        await resolver.resolve("doesnotexist.bla")


async def test_threaded_negative_ipv6_lookup() -> None:
    loop = Mock()
    ips: List[str] = []
    loop.getaddrinfo = fake_ipv6_addrinfo(ips)
    resolver = ThreadedResolver()
    resolver._loop = loop
    with pytest.raises(socket.gaierror):
        await resolver.resolve("doesnotexist.bla")


async def test_threaded_negative_lookup_with_unknown_result() -> None:
    loop = Mock()

    # If compile CPython with `--disable-ipv6` option,
    # we will get an (int, bytes) tuple, instead of a Exception.
    async def unknown_addrinfo(*args: Any, **kwargs: Any) -> _UnknownAddrInfo:
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


async def test_close_for_threaded_resolver(loop: asyncio.AbstractEventLoop) -> None:
    resolver = ThreadedResolver()
    await resolver.close()


@pytest.mark.skipif(aiodns is None, reason="aiodns required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_close_for_async_resolver(loop: asyncio.AbstractEventLoop) -> None:
    resolver = AsyncResolver()
    await resolver.close()


async def test_default_loop_for_threaded_resolver(
    loop: asyncio.AbstractEventLoop,
) -> None:
    asyncio.set_event_loop(loop)
    resolver = ThreadedResolver()
    assert resolver._loop is loop


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_ipv6_positive_lookup(
    loop: asyncio.AbstractEventLoop,
) -> None:
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
        await resolver.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
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
        await resolver.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_error_messages_passed_no_hosts(
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Ensure error messages are passed through from aiodns."""
    with patch("aiodns.DNSResolver", autospec=True, spec_set=True) as mock:
        mock().getaddrinfo.return_value = fake_aiodns_getaddrinfo_ipv6_result([])
        resolver = AsyncResolver()
        with pytest.raises(OSError, match="DNS lookup failed") as excinfo:
            await resolver.resolve("x.org")

        assert excinfo.value.strerror == "DNS lookup failed"
        await resolver.close()


@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_aiodns_not_present(
    loop: asyncio.AbstractEventLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aiohttp.resolver.aiodns", None)
    with pytest.raises(RuntimeError):
        AsyncResolver()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
def test_aio_dns_is_default() -> None:
    assert DefaultResolver is AsyncResolver


@pytest.mark.skipif(getaddrinfo, reason="aiodns <3.2.0 required")
def test_threaded_resolver_is_default() -> None:
    assert DefaultResolver is ThreadedResolver


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_sharing(
    dns_resolver_manager: _DNSResolverManager,
) -> None:
    """Test that the DNSResolverManager shares a resolver among AsyncResolver instances."""
    # Create two default AsyncResolver instances
    resolver1 = AsyncResolver()
    resolver2 = AsyncResolver()

    # Check that they share the same underlying resolver
    assert resolver1._resolver is resolver2._resolver

    # Create an AsyncResolver with custom args
    resolver3 = AsyncResolver(nameservers=["8.8.8.8"])

    # Check that it has its own resolver
    assert resolver1._resolver is not resolver3._resolver

    # Cleanup
    await resolver1.close()
    await resolver2.close()
    await resolver3.close()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_singleton(
    dns_resolver_manager: _DNSResolverManager,
) -> None:
    """Test that DNSResolverManager is a singleton."""
    # Create a second manager and check it's the same instance
    manager1 = dns_resolver_manager
    manager2 = _DNSResolverManager()

    assert manager1 is manager2


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_resolver_lifecycle(
    dns_resolver_manager: _DNSResolverManager,
) -> None:
    """Test that DNSResolverManager creates and destroys resolver correctly."""
    manager = dns_resolver_manager

    # Initially there should be no resolvers
    assert not manager._loop_data

    # Create a mock AsyncResolver for testing
    mock_client = Mock(spec=AsyncResolver)
    mock_client._loop = asyncio.get_running_loop()

    # Getting resolver should create one
    mock_loop = mock_client._loop
    resolver = manager.get_resolver(mock_client, mock_loop)
    assert resolver is not None
    assert manager._loop_data[mock_loop][0] is resolver

    # Getting it again should return the same instance
    assert manager.get_resolver(mock_client, mock_loop) is resolver

    # Clean up
    manager.release_resolver(mock_client, mock_loop)
    assert not manager._loop_data


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_client_registration(
    dns_resolver_manager: _DNSResolverManager,
) -> None:
    """Test client registration and resolver release logic."""
    with patch("aiodns.DNSResolver") as mock:
        # Create resolver instances
        resolver1 = AsyncResolver()
        resolver2 = AsyncResolver()

        # Both should use the same resolver from the manager
        assert resolver1._resolver is resolver2._resolver

        # The manager should be tracking both clients
        assert resolver1._manager is resolver2._manager
        manager = resolver1._manager
        assert manager is not None
        loop = asyncio.get_running_loop()
        _, client_set = manager._loop_data[loop]
        assert len(client_set) == 2

        # Close one resolver
        await resolver1.close()
        _, client_set = manager._loop_data[loop]
        assert len(client_set) == 1

        # Resolver should still exist
        assert manager._loop_data  # Not empty

        # Close the second resolver
        await resolver2.close()
        assert not manager._loop_data  # Should be empty after closing all clients

        # Now all resolvers should be canceled and removed
        assert not manager._loop_data  # Should be empty
        mock().cancel.assert_called_once()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_multiple_event_loops(
    dns_resolver_manager: _DNSResolverManager,
) -> None:
    """Test that DNSResolverManager correctly manages resolvers across different event loops."""
    # Create separate resolvers for each loop
    resolver1 = Mock(name="resolver1")
    resolver2 = Mock(name="resolver2")

    # Create a patch that returns different resolvers based on the loop argument
    mock_resolver = Mock()
    mock_resolver.side_effect = lambda loop=None, **kwargs: (
        resolver1 if loop is asyncio.get_running_loop() else resolver2
    )

    with patch("aiodns.DNSResolver", mock_resolver):
        manager = dns_resolver_manager

        # Create two mock clients on different loops
        mock_client1 = Mock(spec=AsyncResolver)
        mock_client1._loop = asyncio.get_running_loop()

        # Create a second event loop
        loop2 = Mock(spec=asyncio.AbstractEventLoop)
        mock_client2 = Mock(spec=AsyncResolver)
        mock_client2._loop = loop2

        # Get resolvers for both clients
        loop1 = mock_client1._loop
        loop2 = mock_client2._loop

        # Get the resolvers through the manager
        manager_resolver1 = manager.get_resolver(mock_client1, loop1)
        manager_resolver2 = manager.get_resolver(mock_client2, loop2)

        # Should be different resolvers for different loops
        assert manager_resolver1 is resolver1
        assert manager_resolver2 is resolver2
        assert manager._loop_data[loop1][0] is resolver1
        assert manager._loop_data[loop2][0] is resolver2

        # Release the first resolver
        manager.release_resolver(mock_client1, loop1)

        # First loop's resolver should be gone, but second should remain
        assert loop1 not in manager._loop_data
        assert loop2 in manager._loop_data

        # Release the second resolver
        manager.release_resolver(mock_client2, loop2)

        # Both resolvers should be gone
        assert not manager._loop_data

        # Verify resolver cleanup
        resolver1.cancel.assert_called_once()
        resolver2.cancel.assert_called_once()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_weakref_garbage_collection() -> None:
    """Test that release_resolver handles None resolver due to weakref garbage collection."""
    manager = _DNSResolverManager()

    # Create a mock resolver that will be None when accessed
    mock_resolver = Mock()
    mock_resolver.cancel = Mock()

    with patch("aiodns.DNSResolver", return_value=mock_resolver):
        # Create an AsyncResolver to get a resolver from the manager
        resolver = AsyncResolver()
        loop = asyncio.get_running_loop()

        # Manually corrupt the data to simulate garbage collection
        # by setting the resolver to None
        manager._loop_data[loop] = (None, manager._loop_data[loop][1])  # type: ignore[assignment]

        # This should not raise an AttributeError: 'NoneType' object has no attribute 'cancel'
        await resolver.close()

        # Verify no exception was raised and the loop data was cleaned up properly
        # Since we set resolver to None and there was one client, the entry should be removed
        assert loop not in manager._loop_data


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
async def test_dns_resolver_manager_missing_loop_data() -> None:
    """Test that release_resolver handles missing loop data gracefully."""
    manager = _DNSResolverManager()

    with patch("aiodns.DNSResolver"):
        # Create an AsyncResolver
        resolver = AsyncResolver()
        loop = asyncio.get_running_loop()

        # Manually remove the loop data to simulate race condition
        manager._loop_data.clear()

        # This should not raise a KeyError
        await resolver.close()

        # Verify no exception was raised
        assert loop not in manager._loop_data


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_close_multiple_times() -> None:
    """Test that AsyncResolver.close() can be called multiple times without error."""
    with patch("aiodns.DNSResolver") as mock_dns_resolver:
        mock_resolver = Mock()
        mock_resolver.cancel = Mock()
        mock_dns_resolver.return_value = mock_resolver

        # Create a resolver with custom args (dedicated resolver)
        resolver = AsyncResolver(nameservers=["8.8.8.8"])

        # Close it once
        await resolver.close()
        mock_resolver.cancel.assert_called_once()

        # Close it again - should not raise AttributeError
        await resolver.close()
        # cancel should still only be called once
        mock_resolver.cancel.assert_called_once()


@pytest.mark.skipif(not getaddrinfo, reason="aiodns >=3.2.0 required")
@pytest.mark.usefixtures("check_no_lingering_resolvers")
async def test_async_resolver_close_with_none_resolver() -> None:
    """Test that AsyncResolver.close() handles None resolver gracefully."""
    with patch("aiodns.DNSResolver"):
        # Create a resolver with custom args (dedicated resolver)
        resolver = AsyncResolver(nameservers=["8.8.8.8"])

        # Manually set resolver to None to simulate edge case
        resolver._resolver = None  # type: ignore[assignment]

        # This should not raise AttributeError
        await resolver.close()
