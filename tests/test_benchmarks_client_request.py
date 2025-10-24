"""codspeed benchmarks for client requests."""

import asyncio
import sys
from collections.abc import Callable
from http.cookies import BaseCookie
from typing import Any

from multidict import CIMultiDict
from pytest_codspeed import BenchmarkFixture
from yarl import URL

from aiohttp.client_reqrep import (
    ClientRequest,
    ClientRequestArgs,
    ClientResponse,
    ResponseParams,
)
from aiohttp.cookiejar import CookieJar
from aiohttp.helpers import TimerNoop
from aiohttp.http_writer import HttpVersion11
from aiohttp.tracing import Trace

if sys.version_info >= (3, 11):
    from typing import Unpack

    _RequestMaker = Callable[[str, URL, Unpack[ClientRequestArgs]], ClientRequest]
else:
    _RequestMaker = Any


async def test_client_request_update_cookies(
    benchmark: BenchmarkFixture,
    make_client_request: _RequestMaker,
) -> None:
    url = URL("http://python.org")
    req = make_client_request("get", url)
    cookie_jar = CookieJar()
    cookie_jar.update_cookies({"string": "Another string"})
    cookies = cookie_jar.filter_cookies(url)
    assert cookies["string"].value == "Another string"

    @benchmark
    def _run() -> None:
        req._update_cookies(cookies=cookies)


def test_create_client_request_with_cookies(
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    url = URL("http://python.org")
    cookie_jar = CookieJar()
    cookie_jar.update_cookies({"cookie": "value"})
    cookies = cookie_jar.filter_cookies(url)
    assert cookies["cookie"].value == "value"
    timer = TimerNoop()
    timeout = ClientTimeout()
    traces: list[Trace] = []
    headers = CIMultiDict[str]()
    response_params: ResponseParams = {
        "timer": timer,
        "skip_payload": True,
        "read_until_eof": True,
        "auto_decompress": True,
        "read_timeout": timeout.sock_read,
        "read_bufsize": 2**16,
        "timeout_ceil_threshold": 5,
        "max_line_size": 8190,
        "max_field_size": 8190,
    }

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
            response_params=response_params,
            timer=timer,
            timeout=timeout,
            session=None,  # type: ignore[arg-type]
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
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
) -> None:
    url = URL("http://python.org")
    timer = TimerNoop()
    timeout = ClientTimeout()
    traces: list[Trace] = []
    headers = CIMultiDict({"header": "value", "another": "header"})
    cookies = BaseCookie[str]()
    response_params: ResponseParams = {
        "timer": timer,
        "skip_payload": True,
        "read_until_eof": True,
        "auto_decompress": True,
        "read_timeout": timeout.sock_read,
        "read_bufsize": 2**16,
        "timeout_ceil_threshold": 5,
        "max_line_size": 8190,
        "max_field_size": 8190,
    }

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
            response_params=response_params,
            timer=timer,
            timeout=timeout,
            session=None,  # type: ignore[arg-type]
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
    loop: asyncio.AbstractEventLoop,
    benchmark: BenchmarkFixture,
    make_client_request: _RequestMaker,
) -> None:
    url = URL("http://python.org")

    async def make_req() -> ClientRequest:
        """Need async context."""
        return make_client_request("get", url)

    req = loop.run_until_complete(make_req())

    class MockTransport(asyncio.Transport):
        """Mock transport for testing that do no real I/O."""

        def is_closing(self) -> bool:
            """Swallow is_closing."""
            return False

        def write(self, data: bytes | bytearray | memoryview) -> None:
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
            await req._send(conn)  # type: ignore[arg-type]

    @benchmark
    def _run() -> None:
        loop.run_until_complete(send_requests())
