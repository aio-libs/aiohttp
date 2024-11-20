"""codspeed benchmarks for client requests."""

import asyncio
from http.cookies import Morsel
from typing import Union

from pytest_codspeed import BenchmarkFixture
from yarl import URL

from aiohttp.client_reqrep import ClientRequest
from aiohttp.http_writer import HttpVersion11


def test_client_request_update_cookies(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    morsel: "Morsel[str]" = Morsel()
    morsel.set(key="string", val="Another string", coded_val="really")
    morsel_cookie = {"str": morsel}

    @benchmark
    def _run() -> None:
        req.update_cookies(cookies=morsel_cookie)


def test_create_client_request_with_cookies(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    url = URL("http://python.org")

    @benchmark
    def _run() -> None:
        ClientRequest(
            method="get",
            url=url,
            loop=loop,
            headers=None,
            data=None,
            cookies={"cookie": "value"},
            auth=None,
            version=HttpVersion11,
            compress=False,
            chunked=None,
            expect100=False,
        )


def test_create_client_request_with_headers(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    url = URL("http://python.org")

    @benchmark
    def _run() -> None:
        ClientRequest(
            method="get",
            url=url,
            loop=loop,
            headers={"header": "value", "another": "header"},
            data=None,
            cookies=None,
            auth=None,
            version=HttpVersion11,
            compress=False,
            chunked=None,
            expect100=False,
        )


def test_send_client_request_one_hundred(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    url = URL("http://python.org")
    req = ClientRequest("get", url, loop=loop)

    class MockTransport(asyncio.Transport):
        """Mock transport for testing that do no real I/O."""

        def is_closing(self) -> bool:
            """Swallow is_closing."""
            return False

        def write(self, data: Union[bytes, bytearray, memoryview]) -> None:
            """Swallow writes."""

    class MockProtocol(asyncio.BaseProtocol):

        def __init__(self) -> None:
            self.transport = MockTransport()

        @property
        def writing_paused(self) -> bool:
            return False

        async def _drain_helper(self) -> None:
            """Swallow drain."""

        def start_timeout(self) -> None:
            """Swallow start_timeout."""

    class MockConnector:

        def __init__(self) -> None:
            self.force_close = False

    class MockConnection:
        def __init__(self) -> None:
            self.transport = None
            self.protocol = MockProtocol()
            self._connector = MockConnector()

    conn = MockConnection()

    async def send_requests() -> None:
        for _ in range(100):
            await req.send(conn)  # type: ignore[arg-type]

    @benchmark
    def _run() -> None:
        loop.run_until_complete(send_requests())
