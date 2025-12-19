"""codspeed benchmarks for http writer."""

from multidict import CIMultiDict
from pytest_codspeed import BenchmarkFixture

from aiohttp import hdrs
from aiohttp.http_writer import _serialize_headers


def test_serialize_headers(benchmark: BenchmarkFixture) -> None:
    """Benchmark 100 calls to _serialize_headers."""
    status_line = "HTTP/1.1 200 OK"
    headers = CIMultiDict(
        {
            hdrs.CONTENT_TYPE: "text/plain",
            hdrs.CONTENT_LENGTH: "100",
            hdrs.CONNECTION: "keep-alive",
            hdrs.DATE: "Mon, 23 May 2005 22:38:34 GMT",
            hdrs.SERVER: "Test/1.0",
            hdrs.CONTENT_ENCODING: "gzip",
            hdrs.VARY: "Accept-Encoding",
            hdrs.CACHE_CONTROL: "no-cache",
            hdrs.PRAGMA: "no-cache",
            hdrs.EXPIRES: "0",
            hdrs.LAST_MODIFIED: "Mon, 23 May 2005 22:38:34 GMT",
            hdrs.ETAG: "1234567890",
        }
    )

    @benchmark
    def _run() -> None:
        for _ in range(100):
            _serialize_headers(status_line, headers)
