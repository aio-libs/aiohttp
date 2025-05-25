"""codspeed benchmarks for client requests."""

import asyncio
from http.cookies import BaseCookie
from typing import Union

from multidict import CIMultiDict
from pytest_codspeed import BenchmarkFixture
from yarl import URL

from aiohttp.client_reqrep import ClientRequest, ClientResponse
from aiohttp.cookiejar import CookieJar
from aiohttp.helpers import TimerNoop
from aiohttp.http_writer import HttpVersion11
from aiohttp.tracing import Trace


def test_client_request_update_cookies(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    url = URL("http://python.org")
    req = ClientRequest("get", url, loop=loop)
    cookie_jar = CookieJar()
    cookie_jar.update_cookies({"string": "Another string"})
    cookies = cookie_jar.filter_cookies(url)
    assert cookies["string"].value == "Another string"

    @benchmark
    def _run() -> None:
        req.update_cookies(cookies=cookies)


def test_create_client_request_with_cookies(
    loop: asyncio.AbstractEventLoop, benchmark: BenchmarkFixture
) -> None:
    url = URL("http://python.org")
    cookie_jar = CookieJar()
    cookie_jar.update_cookies({"cookie": "value"})
    cookies = cookie_jar.filter_cookies(url)
    assert cookies["cookie"].value == "value"
    timer = TimerNoop()
    traces: list[Trace] = []
    headers = CIMultiDict[str]()

    @benchmark
    def _run() -> None:
        ClientRequest(
            method="get",
            url=url,
            loop=loop,
            params=None,
            skip_auto_headers=None,
            response_class=ClientResponse,
            proxy=None,
            proxy_auth=None,
            proxy_headers=None,
            timer=timer,
            session=None,
            ssl=True,
            traces=traces,
            trust_env=False,
            server_hostname=None,
            headers=headers,
            data=None,
            cookies=cookies,
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
    timer = TimerNoop()
    traces: list[Trace] = []
    headers = CIMultiDict({"header": "value", "another": "header"})
    cookies = BaseCookie[str]()

    @benchmark
    def _run() -> None:
        ClientRequest(
            method="get",
            url=url,
            loop=loop,
            params=None,
            skip_auto_headers=None,
            response_class=ClientResponse,
            proxy=None,
            proxy_auth=None,
            proxy_headers=None,
            timer=timer,
            session=None,
            ssl=True,
            traces=traces,
            trust_env=False,
            server_hostname=None,
            headers=headers,
            data=None,
            cookies=cookies,
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
