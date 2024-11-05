"""codspeed benchmarks for client requests."""

import asyncio
from http.cookies import Morsel

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
