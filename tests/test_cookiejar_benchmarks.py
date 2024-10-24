"""codspeed benchmarks for cookies."""

from http.cookies import BaseCookie

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]
from yarl import URL

from aiohttp.cookiejar import CookieJar


async def test_process_cookies(benchmark: BenchmarkFixture) -> None:
    """Benchmark for creating a temp CookieJar and filtering by URL.

    This benchmark matches what the client request does when cookies
    are passed to the request.
    """
    all_cookies: BaseCookie[str] = BaseCookie()
    url = URL("http://example.com")
    cookies = {"cookie1": "value1", "cookie2": "value2"}

    @benchmark
    def _run() -> None:
        tmp_cookie_jar = CookieJar()
        tmp_cookie_jar.update_cookies(cookies)
        req_cookies = tmp_cookie_jar.filter_cookies(url)
        if req_cookies:
            all_cookies.load(req_cookies)
