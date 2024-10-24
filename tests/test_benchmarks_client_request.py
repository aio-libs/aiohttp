"""codspeed benchmarks for client requests."""

import asyncio
from http.cookies import Morsel

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]
from yarl import URL

from aiohttp.client_reqrep import ClientRequest


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
