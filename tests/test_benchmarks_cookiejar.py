"""codspeed benchmarks for cookies."""

import itertools
from http.cookies import BaseCookie
from typing import TYPE_CHECKING

import pytest
from yarl import URL

from aiohttp.cookiejar import CookieJar, _UnlimitedCookieJar

if TYPE_CHECKING:
    from pytest_codspeed import BenchmarkFixture
else:
    pytest_codspeed = pytest.importorskip("pytest_codspeed")
    BenchmarkFixture = pytest_codspeed.BenchmarkFixture


async def test_load_cookies_into_temp_cookiejar(benchmark: BenchmarkFixture) -> None:
    """Benchmark for creating a temp CookieJar and filtering by URL.

    This benchmark matches what the client request does when cookies
    are passed to the request.
    """
    all_cookies: BaseCookie[str] = BaseCookie()
    url = URL("http://example.com")
    cookies = {"cookie1": "value1", "cookie2": "value2"}

    @benchmark
    def _run() -> None:
        tmp_cookie_jar = _UnlimitedCookieJar()
        tmp_cookie_jar.update_cookies(cookies)
        req_cookies = tmp_cookie_jar.filter_cookies(url)
        all_cookies.load(req_cookies)


async def test_filter_cookies_session_jar(benchmark: BenchmarkFixture) -> None:
    """Benchmark filtering a warm session jar for one request.

    Cookies are split between the host and its parent domain, as a session
    talking to one site typically ends up with.
    """
    jar = CookieJar()
    url = URL("https://www.example.com/app/page")
    jar.update_cookies_from_headers(
        [f"parent{i}=value{i}; Domain=example.com; Path=/" for i in range(25)], url
    )
    jar.update_cookies_from_headers(
        [f"host{i}=value{i}; Path=/app" for i in range(25)], url
    )
    assert len(jar.filter_cookies(url)) == 50

    @benchmark
    def _run() -> None:
        jar.filter_cookies(url)


async def test_update_cookies_from_headers(benchmark: BenchmarkFixture) -> None:
    """Benchmark storing the Set-Cookie fields of one response in a new jar."""
    url = URL("https://www.example.com/")
    headers = [
        f"cookie{i}=value{i}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        for i in range(20)
    ]

    @benchmark
    def _run() -> None:
        CookieJar().update_cookies_from_headers(headers, url)


async def test_update_cookies_from_headers_replacing(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark a response replacing the values of cookies already in the jar."""
    jar = CookieJar()
    url = URL("https://www.example.com/")
    # Alternate values so every call replaces each stored cookie. No expiry,
    # so the jar's expiration state doesn't grow between timed calls.
    header_sets = itertools.cycle(
        [f"cookie{i}={value}{i}; Path=/" for i in range(20)] for value in ("old", "new")
    )
    jar.update_cookies_from_headers(next(header_sets), url)

    @benchmark
    def _run() -> None:
        jar.update_cookies_from_headers(next(header_sets), url)
