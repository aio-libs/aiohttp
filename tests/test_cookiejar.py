import datetime
import heapq
import itertools
import logging
import pickle
from http.cookies import BaseCookie, Morsel, SimpleCookie
from operator import not_
from pathlib import Path
from typing import List, Set, Tuple, Union
from unittest import mock

import pytest
from freezegun import freeze_time
from yarl import URL

from aiohttp import CookieJar, DummyCookieJar
from aiohttp.typedefs import LooseCookies


def dump_cookiejar() -> bytes:  # pragma: no cover
    """Create pickled data for test_pickle_format()."""
    cj = CookieJar()
    cj.update_cookies(_cookies_to_send())
    return pickle.dumps(cj._cookies, pickle.HIGHEST_PROTOCOL)


def _cookies_to_send() -> SimpleCookie:
    return SimpleCookie(
        "shared-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
        "secure-cookie=seventh; Domain=secure.com; Secure; "
        "no-path-cookie=eighth; Domain=pathtest.com; "
        "path1-cookie=ninth; Domain=pathtest.com; Path=/; "
        "path2-cookie=tenth; Domain=pathtest.com; Path=/one; "
        "path3-cookie=eleventh; Domain=pathtest.com; Path=/one/two; "
        "path4-cookie=twelfth; Domain=pathtest.com; Path=/one/two/; "
        "expires-cookie=thirteenth; Domain=expirestest.com; Path=/;"
        " Expires=Tue, 1 Jan 2999 12:00:00 GMT; "
        "max-age-cookie=fourteenth; Domain=maxagetest.com; Path=/;"
        " Max-Age=60; "
        "invalid-max-age-cookie=fifteenth; Domain=invalid-values.com; "
        " Max-Age=string; "
        "invalid-expires-cookie=sixteenth; Domain=invalid-values.com; "
        " Expires=string;"
    )


@pytest.fixture
def cookies_to_send() -> SimpleCookie:
    return _cookies_to_send()


@pytest.fixture
def cookies_to_send_with_expired() -> SimpleCookie:
    return SimpleCookie(
        "shared-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
        "secure-cookie=seventh; Domain=secure.com; Secure; "
        "no-path-cookie=eighth; Domain=pathtest.com; "
        "path1-cookie=ninth; Domain=pathtest.com; Path=/; "
        "path2-cookie=tenth; Domain=pathtest.com; Path=/one; "
        "path3-cookie=eleventh; Domain=pathtest.com; Path=/one/two; "
        "path4-cookie=twelfth; Domain=pathtest.com; Path=/one/two/; "
        "expires-cookie=thirteenth; Domain=expirestest.com; Path=/;"
        " Expires=Tue, 1 Jan 1980 12:00:00 GMT; "
        "max-age-cookie=fourteenth; Domain=maxagetest.com; Path=/;"
        " Max-Age=60; "
        "invalid-max-age-cookie=fifteenth; Domain=invalid-values.com; "
        " Max-Age=string; "
        "invalid-expires-cookie=sixteenth; Domain=invalid-values.com; "
        " Expires=string;"
    )


@pytest.fixture
def cookies_to_receive() -> SimpleCookie:
    return SimpleCookie(
        "unconstrained-cookie=first; Path=/; "
        "domain-cookie=second; Domain=example.com; Path=/; "
        "subdomain1-cookie=third; Domain=test1.example.com; Path=/; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; Path=/; "
        "dotted-domain-cookie=fifth; Domain=.example.com; Path=/; "
        "different-domain-cookie=sixth; Domain=different.org; Path=/; "
        "no-path-cookie=seventh; Domain=pathtest.com; "
        "path-cookie=eighth; Domain=pathtest.com; Path=/somepath; "
        "wrong-path-cookie=ninth; Domain=pathtest.com; Path=somepath;"
    )


def test_date_parsing() -> None:
    parse_func = CookieJar._parse_date
    utc = datetime.timezone.utc

    assert parse_func("") is None

    # 70 -> 1970
    assert (
        parse_func("Tue, 1 Jan 70 00:00:00 GMT")
        == datetime.datetime(1970, 1, 1, tzinfo=utc).timestamp()
    )

    # 10 -> 2010
    assert (
        parse_func("Tue, 1 Jan 10 00:00:00 GMT")
        == datetime.datetime(2010, 1, 1, tzinfo=utc).timestamp()
    )

    # No day of week string
    assert (
        parse_func("1 Jan 1970 00:00:00 GMT")
        == datetime.datetime(1970, 1, 1, tzinfo=utc).timestamp()
    )

    # No timezone string
    assert (
        parse_func("Tue, 1 Jan 1970 00:00:00")
        == datetime.datetime(1970, 1, 1, tzinfo=utc).timestamp()
    )

    # No year
    assert parse_func("Tue, 1 Jan 00:00:00 GMT") is None

    # No month
    assert parse_func("Tue, 1 1970 00:00:00 GMT") is None

    # No day of month
    assert parse_func("Tue, Jan 1970 00:00:00 GMT") is None

    # No time
    assert parse_func("Tue, 1 Jan 1970 GMT") is None

    # Invalid day of month
    assert parse_func("Tue, 0 Jan 1970 00:00:00 GMT") is None

    # Invalid year
    assert parse_func("Tue, 1 Jan 1500 00:00:00 GMT") is None

    # Invalid time
    assert parse_func("Tue, 1 Jan 1970 77:88:99 GMT") is None


def test_domain_matching() -> None:
    test_func = CookieJar._is_domain_match

    assert test_func("test.com", "test.com")
    assert test_func("test.com", "sub.test.com")

    assert not test_func("test.com", "")
    assert not test_func("test.com", "test.org")
    assert not test_func("diff-test.com", "test.com")
    assert not test_func("test.com", "diff-test.com")
    assert not test_func("test.com", "127.0.0.1")


async def test_constructor(
    cookies_to_send: SimpleCookie, cookies_to_receive: SimpleCookie
) -> None:
    jar = CookieJar()
    jar.update_cookies(cookies_to_send)
    jar_cookies = SimpleCookie()
    for cookie in jar:
        dict.__setitem__(jar_cookies, cookie.key, cookie)
    expected_cookies = cookies_to_send
    assert jar_cookies == expected_cookies


async def test_constructor_with_expired(
    cookies_to_send_with_expired: SimpleCookie, cookies_to_receive: SimpleCookie
) -> None:
    jar = CookieJar()
    jar.update_cookies(cookies_to_send_with_expired)
    jar_cookies = SimpleCookie()
    for cookie in jar:
        dict.__setitem__(jar_cookies, cookie.key, cookie)
    expected_cookies = cookies_to_send_with_expired
    assert jar_cookies != expected_cookies


def test_save_load(
    tmp_path: Path,
    cookies_to_send: SimpleCookie,
    cookies_to_receive: SimpleCookie,
) -> None:
    file_path = Path(str(tmp_path)) / "aiohttp.test.cookie"

    # export cookie jar
    jar_save = CookieJar()
    jar_save.update_cookies(cookies_to_receive)
    jar_save.save(file_path=file_path)

    jar_load = CookieJar()
    jar_load.load(file_path=file_path)

    jar_test = SimpleCookie()
    for cookie in jar_load:
        jar_test[cookie.key] = cookie

    assert jar_test == cookies_to_receive


async def test_update_cookie_with_unicode_domain() -> None:
    cookies = (
        "idna-domain-first=first; Domain=xn--9caa.com; Path=/;",
        "idna-domain-second=second; Domain=xn--9caa.com; Path=/;",
    )

    jar = CookieJar()
    jar.update_cookies(SimpleCookie(cookies[0]), URL("http://éé.com/"))
    jar.update_cookies(SimpleCookie(cookies[1]), URL("http://xn--9caa.com/"))

    jar_test = SimpleCookie()
    for cookie in jar:
        jar_test[cookie.key] = cookie

    assert jar_test == SimpleCookie(" ".join(cookies))


async def test_filter_cookie_with_unicode_domain() -> None:
    jar = CookieJar()
    jar.update_cookies(
        SimpleCookie("idna-domain-first=first; Domain=xn--9caa.com; Path=/; ")
    )
    assert len(jar.filter_cookies(URL("http://éé.com"))) == 1
    assert len(jar.filter_cookies(URL("http://xn--9caa.com"))) == 1


async def test_filter_cookies_str_deprecated() -> None:
    jar = CookieJar()
    with pytest.deprecated_call(
        match="The method accepts yarl.URL instances only, got <class 'str'>",
    ):
        jar.filter_cookies("http://éé.com")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("url", "expected_cookies"),
    (
        (
            "http://pathtest.com/one/two/",
            (
                "no-path-cookie",
                "path1-cookie",
                "path2-cookie",
                "shared-cookie",
                "path3-cookie",
                "path4-cookie",
            ),
        ),
        (
            "http://pathtest.com/one/two",
            (
                "no-path-cookie",
                "path1-cookie",
                "path2-cookie",
                "shared-cookie",
                "path3-cookie",
            ),
        ),
        (
            "http://pathtest.com/one/two/three/",
            (
                "no-path-cookie",
                "path1-cookie",
                "path2-cookie",
                "shared-cookie",
                "path3-cookie",
                "path4-cookie",
            ),
        ),
        (
            "http://test1.example.com/",
            (
                "shared-cookie",
                "domain-cookie",
                "subdomain1-cookie",
                "dotted-domain-cookie",
            ),
        ),
        (
            "http://pathtest.com/",
            (
                "shared-cookie",
                "no-path-cookie",
                "path1-cookie",
            ),
        ),
    ),
)
async def test_filter_cookies_with_domain_path_lookup_multilevelpath(
    url: str,
    expected_cookies: Set[str],
) -> None:
    jar = CookieJar()
    cookie = SimpleCookie(
        "shared-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
        "secure-cookie=seventh; Domain=secure.com; Secure; "
        "no-path-cookie=eighth; Domain=pathtest.com; "
        "path1-cookie=ninth; Domain=pathtest.com; Path=/; "
        "path2-cookie=tenth; Domain=pathtest.com; Path=/one; "
        "path3-cookie=eleventh; Domain=pathtest.com; Path=/one/two; "
        "path4-cookie=twelfth; Domain=pathtest.com; Path=/one/two/; "
        "expires-cookie=thirteenth; Domain=expirestest.com; Path=/;"
        " Expires=Tue, 1 Jan 1980 12:00:00 GMT; "
        "max-age-cookie=fourteenth; Domain=maxagetest.com; Path=/;"
        " Max-Age=60; "
        "invalid-max-age-cookie=fifteenth; Domain=invalid-values.com; "
        " Max-Age=string; "
        "invalid-expires-cookie=sixteenth; Domain=invalid-values.com; "
        " Expires=string;"
    )
    jar.update_cookies(cookie)
    cookies = jar.filter_cookies(URL(url))

    assert len(cookies) == len(expected_cookies)
    for c in cookies:
        assert c in expected_cookies


async def test_domain_filter_ip_cookie_send() -> None:
    jar = CookieJar()
    cookies = SimpleCookie(
        "shared-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
        "secure-cookie=seventh; Domain=secure.com; Secure; "
        "no-path-cookie=eighth; Domain=pathtest.com; "
        "path1-cookie=ninth; Domain=pathtest.com; Path=/; "
        "path2-cookie=tenth; Domain=pathtest.com; Path=/one; "
        "path3-cookie=eleventh; Domain=pathtest.com; Path=/one/two; "
        "path4-cookie=twelfth; Domain=pathtest.com; Path=/one/two/; "
        "expires-cookie=thirteenth; Domain=expirestest.com; Path=/;"
        " Expires=Tue, 1 Jan 1980 12:00:00 GMT; "
        "max-age-cookie=fourteenth; Domain=maxagetest.com; Path=/;"
        " Max-Age=60; "
        "invalid-max-age-cookie=fifteenth; Domain=invalid-values.com; "
        " Max-Age=string; "
        "invalid-expires-cookie=sixteenth; Domain=invalid-values.com; "
        " Expires=string;"
    )

    jar.update_cookies(cookies)
    cookies_sent = jar.filter_cookies(URL("http://1.2.3.4/")).output(header="Cookie:")
    assert cookies_sent == "Cookie: shared-cookie=first"


async def test_domain_filter_ip_cookie_receive(
    cookies_to_receive: SimpleCookie,
) -> None:
    jar = CookieJar()

    jar.update_cookies(cookies_to_receive, URL("http://1.2.3.4/"))
    assert len(jar) == 0


@pytest.mark.parametrize(
    ("cookies", "expected", "quote_bool"),
    [
        (
            "shared-cookie=first; ip-cookie=second; Domain=127.0.0.1;",
            "Cookie: ip-cookie=second\r\nCookie: shared-cookie=first",
            True,
        ),
        ('ip-cookie="second"; Domain=127.0.0.1;', 'Cookie: ip-cookie="second"', True),
        ("custom-cookie=value/one;", 'Cookie: custom-cookie="value/one"', True),
        ("custom-cookie=value1;", "Cookie: custom-cookie=value1", True),
        ("custom-cookie=value/one;", "Cookie: custom-cookie=value/one", False),
        ('foo="quoted_value"', 'Cookie: foo="quoted_value"', True),
        ('foo="quoted_value"; domain=127.0.0.1', 'Cookie: foo="quoted_value"', True),
    ],
    ids=(
        "IP domain preserved",
        "no shared cookie",
        "quoted cookie with special char",
        "quoted cookie w/o special char",
        "unquoted cookie with special char",
        "pre-quoted cookie",
        "pre-quoted cookie with domain",
    ),
)
async def test_quotes_correctly_based_on_input(
    cookies: str, expected: str, quote_bool: bool
) -> None:
    jar = CookieJar(unsafe=True, quote_cookie=quote_bool)
    jar.update_cookies(SimpleCookie(cookies))
    cookies_sent = jar.filter_cookies(URL("http://127.0.0.1/")).output(header="Cookie:")
    assert cookies_sent == expected


async def test_ignore_domain_ending_with_dot() -> None:
    jar = CookieJar(unsafe=True)
    jar.update_cookies(
        SimpleCookie("cookie=val; Domain=example.com.;"), URL("http://www.example.com")
    )
    cookies_sent = jar.filter_cookies(URL("http://www.example.com/"))
    assert cookies_sent.output(header="Cookie:") == "Cookie: cookie=val"
    cookies_sent = jar.filter_cookies(URL("http://example.com/"))
    assert cookies_sent.output(header="Cookie:") == ""


class TestCookieJarSafe:
    @pytest.fixture(autouse=True)
    def setup_cookies(
        self,
        cookies_to_send_with_expired: SimpleCookie,
        cookies_to_receive: SimpleCookie,
    ) -> None:
        self.cookies_to_send = cookies_to_send_with_expired
        self.cookies_to_receive = cookies_to_receive

    def request_reply_with_same_url(
        self, url: str
    ) -> Tuple["BaseCookie[str]", SimpleCookie]:
        jar = CookieJar()
        jar.update_cookies(self.cookies_to_send)
        cookies_sent = jar.filter_cookies(URL(url))

        jar.clear()

        jar.update_cookies(self.cookies_to_receive, URL(url))
        cookies_received = SimpleCookie()
        for cookie in jar:
            dict.__setitem__(cookies_received, cookie.key, cookie)

        jar.clear()

        return cookies_sent, cookies_received

    def timed_request(
        self, url: str, update_time: float, send_time: float
    ) -> "BaseCookie[str]":
        jar = CookieJar()
        freeze_update_time: Union[datetime.datetime, datetime.timedelta]
        freeze_send_time: Union[datetime.datetime, datetime.timedelta]
        if isinstance(update_time, int):
            freeze_update_time = datetime.timedelta(seconds=update_time)
        else:
            freeze_update_time = datetime.datetime.fromtimestamp(update_time)
        if isinstance(send_time, int):
            freeze_send_time = datetime.timedelta(seconds=send_time)
        else:
            freeze_send_time = datetime.datetime.fromtimestamp(send_time)

        with freeze_time(freeze_update_time):
            jar.update_cookies(self.cookies_to_send)

        with freeze_time(freeze_send_time):
            cookies_sent = jar.filter_cookies(URL(url))

        jar.clear()

        return cookies_sent

    def test_domain_filter_same_host(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://example.com/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "domain-cookie",
            "dotted-domain-cookie",
        }

        assert set(cookies_received.keys()) == {
            "unconstrained-cookie",
            "domain-cookie",
            "dotted-domain-cookie",
        }

    def test_domain_filter_same_host_and_subdomain(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://test1.example.com/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "domain-cookie",
            "subdomain1-cookie",
            "dotted-domain-cookie",
        }

        assert set(cookies_received.keys()) == {
            "unconstrained-cookie",
            "domain-cookie",
            "subdomain1-cookie",
            "dotted-domain-cookie",
        }

    def test_domain_filter_same_host_diff_subdomain(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://different.example.com/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "domain-cookie",
            "dotted-domain-cookie",
        }

        assert set(cookies_received.keys()) == {
            "unconstrained-cookie",
            "domain-cookie",
            "dotted-domain-cookie",
        }

    def test_domain_filter_diff_host(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://different.org/"
        )

        assert set(cookies_sent.keys()) == {"shared-cookie", "different-domain-cookie"}

        assert set(cookies_received.keys()) == {
            "unconstrained-cookie",
            "different-domain-cookie",
        }

    def test_domain_filter_host_only(self, cookies_to_receive: SimpleCookie) -> None:
        jar = CookieJar()
        jar.update_cookies(cookies_to_receive, URL("http://example.com/"))
        sub_cookie = SimpleCookie("subdomain=spam; Path=/;")
        jar.update_cookies(sub_cookie, URL("http://foo.example.com/"))

        cookies_sent = jar.filter_cookies(URL("http://foo.example.com/"))
        assert "subdomain" in set(cookies_sent.keys())
        assert "unconstrained-cookie" not in set(cookies_sent.keys())

    def test_secure_filter(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url("http://secure.com/")

        assert set(cookies_sent.keys()) == {"shared-cookie"}

        cookies_sent, _ = self.request_reply_with_same_url("https://secure.com/")

        assert set(cookies_sent.keys()) == {"shared-cookie", "secure-cookie"}

    def test_path_filter_root(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url("http://pathtest.com/")

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
        }

    def test_path_filter_folder(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url("http://pathtest.com/one/")

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
        }

    def test_path_filter_file(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
            "path3-cookie",
        }

    def test_path_filter_subfolder(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
            "path3-cookie",
            "path4-cookie",
        }

    def test_path_filter_subsubfolder(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two/three/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
            "path3-cookie",
            "path4-cookie",
        }

    def test_path_filter_different_folder(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/hundred/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
        }

    def test_path_value(self) -> None:
        _, cookies_received = self.request_reply_with_same_url("http://pathtest.com/")

        assert set(cookies_received.keys()) == {
            "unconstrained-cookie",
            "no-path-cookie",
            "path-cookie",
            "wrong-path-cookie",
        }

        assert cookies_received["no-path-cookie"]["path"] == "/"
        assert cookies_received["path-cookie"]["path"] == "/somepath"
        assert cookies_received["wrong-path-cookie"]["path"] == "/"

    def test_expires(self) -> None:
        ts_before = datetime.datetime(
            1975, 1, 1, tzinfo=datetime.timezone.utc
        ).timestamp()

        ts_after = datetime.datetime(
            2030, 1, 1, tzinfo=datetime.timezone.utc
        ).timestamp()

        cookies_sent = self.timed_request(
            "http://expirestest.com/", ts_before, ts_before
        )

        assert set(cookies_sent.keys()) == {"shared-cookie", "expires-cookie"}

        cookies_sent = self.timed_request(
            "http://expirestest.com/", ts_before, ts_after
        )

        assert set(cookies_sent.keys()) == {"shared-cookie"}

    def test_max_age(self) -> None:
        cookies_sent = self.timed_request("http://maxagetest.com/", 1000, 1000)

        assert set(cookies_sent.keys()) == {"shared-cookie", "max-age-cookie"}

        cookies_sent = self.timed_request("http://maxagetest.com/", 1000, 2000)

        assert set(cookies_sent.keys()) == {"shared-cookie"}

    def test_invalid_values(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://invalid-values.com/"
        )

        assert set(cookies_sent.keys()) == {
            "shared-cookie",
            "invalid-max-age-cookie",
            "invalid-expires-cookie",
        }

        cookie = cookies_sent["invalid-max-age-cookie"]
        assert cookie["max-age"] == ""

        cookie = cookies_sent["invalid-expires-cookie"]
        assert cookie["expires"] == ""

    async def test_cookie_not_expired_when_added_after_removal(self) -> None:
        # Test case for https://github.com/aio-libs/aiohttp/issues/2084
        timestamps = [
            533588.993,
            533588.993,
            533588.993,
            533588.993,
            533589.093,
            533589.093,
        ]

        loop = mock.Mock()
        loop.time.side_effect = itertools.chain(
            timestamps, itertools.cycle([timestamps[-1]])
        )

        jar = CookieJar(unsafe=True)
        # Remove `foo` cookie.
        jar.update_cookies(SimpleCookie('foo=""; Max-Age=0'))
        # Set `foo` cookie to `bar`.
        jar.update_cookies(SimpleCookie('foo="bar"'))

        # Assert that there is a cookie.
        assert len(jar) == 1

    async def test_path_filter_diff_folder_same_name(self) -> None:
        jar = CookieJar(unsafe=True)

        jar.update_cookies(
            SimpleCookie("path-cookie=zero; Domain=pathtest.com; Path=/; ")
        )
        jar.update_cookies(
            SimpleCookie("path-cookie=one; Domain=pathtest.com; Path=/one; ")
        )
        assert len(jar) == 2

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/"))
        assert len(jar_filtered) == 1
        assert jar_filtered["path-cookie"].value == "zero"

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/one"))
        assert len(jar_filtered) == 1
        assert jar_filtered["path-cookie"].value == "one"

    async def test_path_filter_diff_folder_same_name_return_best_match_independent_from_put_order(
        self,
    ) -> None:
        jar = CookieJar(unsafe=True)
        jar.update_cookies(
            SimpleCookie("path-cookie=one; Domain=pathtest.com; Path=/one; ")
        )
        jar.update_cookies(
            SimpleCookie("path-cookie=zero; Domain=pathtest.com; Path=/; ")
        )
        jar.update_cookies(
            SimpleCookie("path-cookie=two; Domain=pathtest.com; Path=/second; ")
        )
        assert len(jar) == 3

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/"))
        assert len(jar_filtered) == 1
        assert jar_filtered["path-cookie"].value == "zero"

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/second"))
        assert len(jar_filtered) == 1
        assert jar_filtered["path-cookie"].value == "two"

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/one"))
        assert len(jar_filtered) == 1
        assert jar_filtered["path-cookie"].value == "one"


async def test_dummy_cookie_jar() -> None:
    cookie = SimpleCookie("foo=bar; Domain=example.com;")
    dummy_jar = DummyCookieJar()
    assert dummy_jar.quote_cookie is True
    assert len(dummy_jar) == 0
    dummy_jar.update_cookies(cookie)
    assert len(dummy_jar) == 0
    with pytest.raises(StopIteration):
        next(iter(dummy_jar))
    assert not dummy_jar.filter_cookies(URL("http://example.com/"))
    dummy_jar.clear()


async def test_loose_cookies_types() -> None:
    jar = CookieJar()

    accepted_types: tuple[LooseCookies, ...] = (
        [("str", BaseCookie())],
        [("str", Morsel())],
        [("str", "str")],
        {"str": BaseCookie()},
        {"str": Morsel()},
        {"str": "str"},
        SimpleCookie(),
    )

    for loose_cookies_type in accepted_types:
        jar.update_cookies(cookies=loose_cookies_type)


async def test_cookie_jar_clear_all() -> None:
    sut = CookieJar()
    cookie = SimpleCookie()
    cookie["foo"] = "bar"
    sut.update_cookies(cookie)

    sut.clear()
    assert len(sut) == 0


async def test_cookie_jar_clear_expired() -> None:
    sut = CookieJar()

    cookie = SimpleCookie()

    cookie["foo"] = "bar"
    cookie["foo"]["expires"] = "Tue, 1 Jan 1990 12:00:00 GMT"

    with freeze_time("1980-01-01"):
        sut.update_cookies(cookie)

    for _ in range(2):
        sut.clear(not_)
        with freeze_time("1980-01-01"):
            assert len(sut) == 0


async def test_cookie_jar_expired_changes() -> None:
    """Test that expire time changes are handled as expected."""
    jar = CookieJar()

    cookie_eleven_am = SimpleCookie()
    cookie_eleven_am["foo"] = "bar"
    cookie_eleven_am["foo"]["expires"] = "Tue, 1 Jan 1990 11:00:00 GMT"

    cookie_noon = SimpleCookie()
    cookie_noon["foo"] = "bar"
    cookie_noon["foo"]["expires"] = "Tue, 1 Jan 1990 12:00:00 GMT"

    cookie_one_pm = SimpleCookie()
    cookie_one_pm["foo"] = "bar"
    cookie_one_pm["foo"]["expires"] = "Tue, 1 Jan 1990 13:00:00 GMT"

    cookie_two_pm = SimpleCookie()
    cookie_two_pm["foo"] = "bar"
    cookie_two_pm["foo"]["expires"] = "Tue, 1 Jan 1990 14:00:00 GMT"

    with freeze_time() as freezer:
        freezer.move_to("1990-01-01 10:00:00+00:00")
        jar.update_cookies(cookie_noon)
        assert len(jar) == 1
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies

        jar.update_cookies(cookie_eleven_am)
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies

        jar.update_cookies(cookie_one_pm)
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies

        jar.update_cookies(cookie_two_pm)
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies

        freezer.move_to("1990-01-01 13:00:00+00:00")
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies

        freezer.move_to("1990-01-01 14:00:00+00:00")
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 0


async def test_cookie_jar_duplicates_with_expire_heap() -> None:
    """Test that duplicate cookies do not grow the expires heap."""
    jar = CookieJar()

    cookie_eleven_am = SimpleCookie()
    cookie_eleven_am["foo"] = "bar"
    cookie_eleven_am["foo"]["expires"] = "Tue, 1 Jan 1990 11:00:00 GMT"

    cookie_two_pm = SimpleCookie()
    cookie_two_pm["foo"] = "bar"
    cookie_two_pm["foo"]["expires"] = "Tue, 1 Jan 1990 14:00:00 GMT"

    with freeze_time() as freezer:
        freezer.move_to("1990-01-01 10:00:00+00:00")

        for _ in range(10):
            jar.update_cookies(cookie_eleven_am)

        assert len(jar) == 1
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies

        assert len(jar._expire_heap) == 1

        freezer.move_to("1990-01-01 16:00:00+00:00")
        jar.update_cookies(cookie_two_pm)
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 0
        assert len(jar._expire_heap) == 0


async def test_cookie_jar_filter_cookies_expires() -> None:
    """Test that calling filter_cookies will expire stale cookies."""
    jar = CookieJar()
    assert len(jar) == 0

    cookie = SimpleCookie()

    cookie["foo"] = "bar"
    cookie["foo"]["expires"] = "Tue, 1 Jan 1990 12:00:00 GMT"

    with freeze_time("1980-01-01"):
        jar.update_cookies(cookie)

    assert len(jar) == 1

    # filter_cookies should expire stale cookies
    jar.filter_cookies(URL("http://any.com/"))

    assert len(jar) == 0


async def test_cookie_jar_heap_cleanup() -> None:
    """Test that the heap gets cleaned up when there are many old expirations."""
    jar = CookieJar()
    # The heap should not be cleaned up when there are less than 100 expiration changes
    min_cookies_to_cleanup = 100

    with freeze_time() as freezer:
        freezer.move_to("1990-01-01 09:00:00+00:00")

        start_time = datetime.datetime(
            1990, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc
        )
        for i in range(min_cookies_to_cleanup):
            cookie = SimpleCookie()
            cookie["foo"] = "bar"
            cookie["foo"]["expires"] = (
                start_time + datetime.timedelta(seconds=i)
            ).strftime("%a, %d %b %Y %H:%M:%S GMT")
            jar.update_cookies(cookie)
            assert len(jar._expire_heap) == i + 1

        assert len(jar._expire_heap) == min_cookies_to_cleanup

        # Now that we reached the minimum number of cookies to cleanup,
        # add one more cookie to trigger the cleanup
        cookie = SimpleCookie()
        cookie["foo"] = "bar"
        cookie["foo"]["expires"] = (
            start_time + datetime.timedelta(seconds=i + 1)
        ).strftime("%a, %d %b %Y %H:%M:%S GMT")
        jar.update_cookies(cookie)

        # Verify that the heap has been cleaned up
        assert len(jar) == 1
        matched_cookies = jar.filter_cookies(URL("/"))
        assert len(matched_cookies) == 1
        assert "foo" in matched_cookies
        # The heap should have been cleaned up
        assert len(jar._expire_heap) == 1


async def test_cookie_jar_heap_maintains_order_after_cleanup() -> None:
    """Test that order is maintained after cleanup."""
    jar = CookieJar()
    # The heap should not be cleaned up when there are less than 100 expiration changes
    min_cookies_to_cleanup = 100

    with freeze_time() as freezer:
        freezer.move_to("1990-01-01 09:00:00+00:00")

        for hour in (12, 13):
            for i in range(min_cookies_to_cleanup):
                cookie = SimpleCookie()
                cookie["foo"] = "bar"
                cookie["foo"]["domain"] = f"example{i}.com"
                cookie["foo"]["expires"] = f"Tue, 1 Jan 1990 {hour}:00:00 GMT"
                jar.update_cookies(cookie)

        # Get the jar into a state where the next cookie will trigger the cleanup
        assert len(jar._expire_heap) == min_cookies_to_cleanup * 2
        assert len(jar._expirations) == min_cookies_to_cleanup

        cookie = SimpleCookie()
        cookie["foo"] = "bar"
        cookie["foo"]["domain"] = "example0.com"
        cookie["foo"]["expires"] = "Tue, 1 Jan 1990 14:00:00 GMT"
        jar.update_cookies(cookie)

        assert len(jar) == 100
        # The heap should have been cleaned up
        assert len(jar._expire_heap) == 100

        # Verify that the heap is still ordered
        heap_before = jar._expire_heap.copy()
        heapq.heapify(jar._expire_heap)
        assert heap_before == jar._expire_heap


async def test_cookie_jar_clear_domain() -> None:
    sut = CookieJar()
    cookie = SimpleCookie()
    cookie["foo"] = "bar"
    cookie["domain_cookie"] = "value"
    cookie["domain_cookie"]["domain"] = "example.com"
    cookie["subdomain_cookie"] = "value"
    cookie["subdomain_cookie"]["domain"] = "test.example.com"
    sut.update_cookies(cookie)

    sut.clear_domain("example.com")
    iterator = iter(sut)
    morsel = next(iterator)
    assert morsel.key == "foo"
    assert morsel.value == "bar"
    with pytest.raises(StopIteration):
        next(iterator)


def test_pickle_format(cookies_to_send: SimpleCookie) -> None:
    """Test if cookiejar pickle format breaks.

    If this test fails, it may indicate that saved cookiejars will stop working.
    If that happens then:
        1. Avoid releasing the change in a bugfix release.
        2. Try to include a migration script in the release notes (example below).
        3. Use dump_cookiejar() at the top of this file to update `pickled`.

    Depending on the changes made, a migration script might look like:
        import pickle
        with file_path.open("rb") as f:
            cookies = pickle.load(f)

        morsels = [(name, m) for c in cookies.values() for name, m in c.items()]
        cookies.clear()
        for name, m in morsels:
            cookies[(m["domain"], m["path"])][name] = m

        with file_path.open("wb") as f:
            pickle.dump(cookies, f, pickle.HIGHEST_PROTOCOL)
    """
    pickled = b"\x80\x04\x95\xc8\x0b\x00\x00\x00\x00\x00\x00\x8c\x0bcollections\x94\x8c\x0bdefaultdict\x94\x93\x94\x8c\x0chttp.cookies\x94\x8c\x0cSimpleCookie\x94\x93\x94\x85\x94R\x94(\x8c\x00\x94h\x08\x86\x94h\x05)\x81\x94\x8c\rshared-cookie\x94h\x03\x8c\x06Morsel\x94\x93\x94)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94\x8c\x01/\x94\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\x08\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(\x8c\x03key\x94h\x0b\x8c\x05value\x94\x8c\x05first\x94\x8c\x0bcoded_value\x94h\x1cubs\x8c\x0bexample.com\x94h\x08\x86\x94h\x05)\x81\x94(\x8c\rdomain-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\x1e\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah!h\x1b\x8c\x06second\x94h\x1dh-ub\x8c\x14dotted-domain-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94\x8c\x0bexample.com\x94\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah.h\x1b\x8c\x05fifth\x94h\x1dh;ubu\x8c\x11test1.example.com\x94h\x08\x86\x94h\x05)\x81\x94\x8c\x11subdomain1-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h<\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah?h\x1b\x8c\x05third\x94h\x1dhKubs\x8c\x11test2.example.com\x94h\x08\x86\x94h\x05)\x81\x94\x8c\x11subdomain2-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94hL\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ahOh\x1b\x8c\x06fourth\x94h\x1dh[ubs\x8c\rdifferent.org\x94h\x08\x86\x94h\x05)\x81\x94\x8c\x17different-domain-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\\\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah_h\x1b\x8c\x05sixth\x94h\x1dhkubs\x8c\nsecure.com\x94h\x08\x86\x94h\x05)\x81\x94\x8c\rsecure-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94hl\x8c\x07max-age\x94h\x08\x8c\x06secure\x94\x88\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ahoh\x1b\x8c\x07seventh\x94h\x1dh{ubs\x8c\x0cpathtest.com\x94h\x08\x86\x94h\x05)\x81\x94(\x8c\x0eno-path-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h|\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\x7fh\x1b\x8c\x06eighth\x94h\x1dh\x8bub\x8c\x0cpath1-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94\x8c\x0cpathtest.com\x94\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\x8ch\x1b\x8c\x05ninth\x94h\x1dh\x99ubu\x8c\x0cpathtest.com\x94\x8c\x04/one\x94\x86\x94h\x05)\x81\x94\x8c\x0cpath2-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x9b\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\x9a\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\x9eh\x1b\x8c\x05tenth\x94h\x1dh\xaaubs\x8c\x0cpathtest.com\x94\x8c\x08/one/two\x94\x86\x94h\x05)\x81\x94(\x8c\x0cpath3-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\xac\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\xab\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\xafh\x1b\x8c\x08eleventh\x94h\x1dh\xbbub\x8c\x0cpath4-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94\x8c\t/one/two/\x94\x8c\x07comment\x94h\x08\x8c\x06domain\x94\x8c\x0cpathtest.com\x94\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\xbch\x1b\x8c\x07twelfth\x94h\x1dh\xcaubu\x8c\x0fexpirestest.com\x94h\x08\x86\x94h\x05)\x81\x94\x8c\x0eexpires-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94\x8c\x1cTue, 1 Jan 2999 12:00:00 GMT\x94\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\xcb\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\xceh\x1b\x8c\nthirteenth\x94h\x1dh\xdbubs\x8c\x0emaxagetest.com\x94h\x08\x86\x94h\x05)\x81\x94\x8c\x0emax-age-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\xdc\x8c\x07max-age\x94\x8c\x0260\x94\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\xdfh\x1b\x8c\nfourteenth\x94h\x1dh\xecubs\x8c\x12invalid-values.com\x94h\x08\x86\x94h\x05)\x81\x94(\x8c\x16invalid-max-age-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94h\xed\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\xf0h\x1b\x8c\tfifteenth\x94h\x1dh\xfcub\x8c\x16invalid-expires-cookie\x94h\r)\x81\x94(\x8c\x07expires\x94h\x08\x8c\x04path\x94h\x11\x8c\x07comment\x94h\x08\x8c\x06domain\x94\x8c\x12invalid-values.com\x94\x8c\x07max-age\x94h\x08\x8c\x06secure\x94h\x08\x8c\x08httponly\x94h\x08\x8c\x07version\x94h\x08\x8c\x08samesite\x94h\x08u}\x94(h\x1ah\xfdh\x1b\x8c\tsixteenth\x94h\x1dj\n\x01\x00\x00ubuu."
    cookies = pickle.loads(pickled)

    cj = CookieJar()
    cj.update_cookies(cookies_to_send)

    assert cookies == cj._cookies


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/index.html",
        URL("http://127.0.0.1/index.html"),
        ["http://127.0.0.1/index.html"],
        [URL("http://127.0.0.1/index.html")],
    ],
)
async def test_treat_as_secure_origin_init(
    url: Union[str, URL, List[str], List[URL]],
) -> None:
    jar = CookieJar(unsafe=True, treat_as_secure_origin=url)
    assert jar._treat_as_secure_origin == frozenset({URL("http://127.0.0.1")})


async def test_treat_as_secure_origin() -> None:
    endpoint = URL("http://127.0.0.1/")

    jar = CookieJar(unsafe=True, treat_as_secure_origin=[endpoint])
    secure_cookie = SimpleCookie(
        "cookie-key=cookie-value; HttpOnly; Path=/; Secure",
    )

    jar.update_cookies(
        secure_cookie,
        endpoint,
    )

    assert len(jar) == 1
    filtered_cookies = jar.filter_cookies(request_url=endpoint)
    assert len(filtered_cookies) == 1


async def test_filter_cookies_does_not_leak_memory() -> None:
    """Test that filter_cookies doesn't create empty cookie entries.

    Regression test for https://github.com/aio-libs/aiohttp/issues/11052
    """
    jar = CookieJar()

    # Set a cookie with Path=/
    jar.update_cookies({"test_cookie": "value; Path=/"}, URL("http://example.com/"))

    # Check initial state
    assert len(jar) == 1
    initial_storage_size = len(jar._cookies)
    initial_morsel_cache_size = len(jar._morsel_cache)

    # Make multiple requests with different paths
    paths = [
        "/",
        "/api",
        "/api/v1",
        "/api/v1/users",
        "/api/v1/users/123",
        "/static/css/style.css",
        "/images/logo.png",
    ]

    for path in paths:
        url = URL(f"http://example.com{path}")
        filtered = jar.filter_cookies(url)
        # Should still get the cookie
        assert len(filtered) == 1
        assert "test_cookie" in filtered

    # Storage size should not grow significantly
    # Only the shared cookie entry ('', '') may be added
    final_storage_size = len(jar._cookies)
    assert final_storage_size <= initial_storage_size + 1

    # Verify _morsel_cache doesn't leak either
    # It should only have entries for domains/paths where cookies exist
    final_morsel_cache_size = len(jar._morsel_cache)
    assert final_morsel_cache_size <= initial_morsel_cache_size + 1

    # Verify no empty entries were created for domain-path combinations
    for key, cookies in jar._cookies.items():
        if key != ("", ""):  # Skip the shared cookie entry
            assert len(cookies) > 0, f"Empty cookie entry found for {key}"

    # Verify _morsel_cache entries correspond to actual cookies
    for key, morsels in jar._morsel_cache.items():
        assert key in jar._cookies, f"Orphaned morsel cache entry for {key}"
        assert len(morsels) > 0, f"Empty morsel cache entry found for {key}"


def test_update_cookies_from_headers() -> None:
    """Test update_cookies_from_headers method."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/path")

    # Test with simple cookies
    headers = [
        "session-id=123456; Path=/",
        "user-pref=dark-mode; Domain=.example.com",
        "tracking=xyz789; Secure; HttpOnly",
    ]

    jar.update_cookies_from_headers(headers, url)

    # Verify all cookies were added to the jar
    assert len(jar) == 3

    # Check cookies available for HTTP URL (secure cookie should be filtered out)
    filtered_http: BaseCookie[str] = jar.filter_cookies(url)
    assert len(filtered_http) == 2
    assert "session-id" in filtered_http
    assert filtered_http["session-id"].value == "123456"
    assert "user-pref" in filtered_http
    assert filtered_http["user-pref"].value == "dark-mode"
    assert "tracking" not in filtered_http  # Secure cookie not available on HTTP

    # Check cookies available for HTTPS URL (all cookies should be available)
    url_https: URL = URL("https://example.com/path")
    filtered_https: BaseCookie[str] = jar.filter_cookies(url_https)
    assert len(filtered_https) == 3
    assert "tracking" in filtered_https
    assert filtered_https["tracking"].value == "xyz789"


def test_update_cookies_from_headers_duplicate_names() -> None:
    """Test that duplicate cookie names with different domains are preserved."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://www.example.com/")

    # Headers with duplicate names but different domains
    headers = [
        "session-id=123456; Domain=.example.com; Path=/",
        "session-id=789012; Domain=.www.example.com; Path=/",
        "user-pref=light; Domain=.example.com",
        "user-pref=dark; Domain=sub.example.com",
    ]

    jar.update_cookies_from_headers(headers, url)

    # Should have 3 cookies (user-pref=dark for sub.example.com is rejected)
    assert len(jar) == 3

    # Verify we have both session-id cookies
    all_cookies: List[Morsel[str]] = list(jar)
    session_ids: List[Morsel[str]] = [c for c in all_cookies if c.key == "session-id"]
    assert len(session_ids) == 2

    # Check their domains are different
    domains: Set[str] = {c["domain"] for c in session_ids}
    assert domains == {"example.com", "www.example.com"}


def test_update_cookies_from_headers_invalid_cookies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that invalid cookies are logged and skipped."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/")

    # Mix of valid and invalid cookies
    headers = [
        "valid-cookie=value123",
        "invalid,cookie=value; "  # Comma character is not allowed
        "HttpOnly; Path=/",
        "another-valid=value456",
    ]

    # Enable logging for the client logger
    with caplog.at_level(logging.WARNING, logger="aiohttp.client"):
        jar.update_cookies_from_headers(headers, url)

    # Check that we logged warnings for invalid cookies
    assert "Can not load cookies" in caplog.text

    # Valid cookies should still be added
    assert len(jar) >= 2  # At least the two clearly valid cookies
    filtered: BaseCookie[str] = jar.filter_cookies(url)
    assert "valid-cookie" in filtered
    assert "another-valid" in filtered


def test_update_cookies_from_headers_with_curly_braces() -> None:
    """Test that cookies with curly braces in names are now accepted (#2683)."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/")

    # Cookie names with curly braces should now be accepted
    headers = [
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}="
        "{925EC0B8-CB17-4BEB-8A35-1033813B0523}; "
        "HttpOnly; Path=/",
        "regular-cookie=value123",
    ]

    jar.update_cookies_from_headers(headers, url)

    # Both cookies should be added
    assert len(jar) == 2
    filtered: BaseCookie[str] = jar.filter_cookies(url)
    assert "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}" in filtered
    assert "regular-cookie" in filtered


def test_update_cookies_from_headers_with_special_chars() -> None:
    """Test that cookies with various special characters are accepted."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/")

    # Various special characters that should now be accepted
    headers = [
        "cookie_with_parens=(value)=test123",
        "cookie-with-brackets[index]=value456",
        "cookie@with@at=value789",
        "cookie:with:colons=value000",
    ]

    jar.update_cookies_from_headers(headers, url)

    # All cookies should be added
    assert len(jar) == 4
    filtered: BaseCookie[str] = jar.filter_cookies(url)
    assert "cookie_with_parens" in filtered
    assert "cookie-with-brackets[index]" in filtered
    assert "cookie@with@at" in filtered
    assert "cookie:with:colons" in filtered


def test_update_cookies_from_headers_empty_list() -> None:
    """Test that empty header list is handled gracefully."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/")

    # Should not raise any errors
    jar.update_cookies_from_headers([], url)

    assert len(jar) == 0


def test_update_cookies_from_headers_with_attributes() -> None:
    """Test cookies with various attributes are handled correctly."""
    jar: CookieJar = CookieJar()
    url: URL = URL("https://secure.example.com/app/page")

    headers = [
        "secure-cookie=value1; Secure; HttpOnly; SameSite=Strict",
        "expiring-cookie=value2; Max-Age=3600; Path=/app",
        "domain-cookie=value3; Domain=.example.com; Path=/",
        "dated-cookie=value4; Expires=Wed, 09 Jun 2030 10:18:14 GMT",
    ]

    jar.update_cookies_from_headers(headers, url)

    # All cookies should be stored
    assert len(jar) == 4

    # Verify secure cookie (should work on HTTPS subdomain)
    # Note: cookies without explicit path get path from URL (/app)
    filtered_https_root: BaseCookie[str] = jar.filter_cookies(
        URL("https://secure.example.com/")
    )
    assert len(filtered_https_root) == 1  # Only domain-cookie has Path=/
    assert "domain-cookie" in filtered_https_root

    # Check app path
    filtered_https_app: BaseCookie[str] = jar.filter_cookies(
        URL("https://secure.example.com/app/")
    )
    assert len(filtered_https_app) == 4  # All cookies match
    assert "secure-cookie" in filtered_https_app
    assert "expiring-cookie" in filtered_https_app
    assert "domain-cookie" in filtered_https_app
    assert "dated-cookie" in filtered_https_app

    # Secure cookie should not be available on HTTP
    filtered_http_app: BaseCookie[str] = jar.filter_cookies(
        URL("http://secure.example.com/app/")
    )
    assert "secure-cookie" not in filtered_http_app
    assert "expiring-cookie" in filtered_http_app  # Non-secure cookies still available
    assert "domain-cookie" in filtered_http_app
    assert "dated-cookie" in filtered_http_app


def test_update_cookies_from_headers_preserves_existing() -> None:
    """Test that update_cookies_from_headers preserves existing cookies."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/")

    # Add some initial cookies
    jar.update_cookies(
        {
            "existing1": "value1",
            "existing2": "value2",
        },
        url,
    )

    # Add more cookies via headers
    headers = [
        "new-cookie1=value3",
        "new-cookie2=value4",
    ]

    jar.update_cookies_from_headers(headers, url)

    # Should have all 4 cookies
    assert len(jar) == 4
    filtered: BaseCookie[str] = jar.filter_cookies(url)
    assert "existing1" in filtered
    assert "existing2" in filtered
    assert "new-cookie1" in filtered
    assert "new-cookie2" in filtered


def test_update_cookies_from_headers_overwrites_same_cookie() -> None:
    """Test that cookies with same name/domain/path are overwritten."""
    jar: CookieJar = CookieJar()
    url: URL = URL("http://example.com/")

    # Add initial cookie
    jar.update_cookies({"session": "old-value"}, url)

    # Update with new value via headers
    headers = ["session=new-value"]
    jar.update_cookies_from_headers(headers, url)

    # Should still have just 1 cookie with updated value
    assert len(jar) == 1
    filtered: BaseCookie[str] = jar.filter_cookies(url)
    assert filtered["session"].value == "new-value"


def test_dummy_cookie_jar_update_cookies_from_headers() -> None:
    """Test that DummyCookieJar ignores update_cookies_from_headers."""
    jar: DummyCookieJar = DummyCookieJar()
    url: URL = URL("http://example.com/")

    headers = [
        "cookie1=value1",
        "cookie2=value2",
    ]

    # Should not raise and should not store anything
    jar.update_cookies_from_headers(headers, url)

    assert len(jar) == 0
    filtered: BaseCookie[str] = jar.filter_cookies(url)
    assert len(filtered) == 0


async def test_shared_cookie_cache_population() -> None:
    """Test that shared cookies are cached correctly."""
    jar = CookieJar(unsafe=True)

    # Create a shared cookie (no domain/path restrictions)
    sc = SimpleCookie()
    sc["shared"] = "value"
    sc["shared"]["path"] = "/"  # Will be stripped to ""

    # Update with empty URL to avoid domain being set
    jar.update_cookies(sc, URL())

    # Verify cookie is stored at shared key
    assert ("", "") in jar._cookies
    assert "shared" in jar._cookies[("", "")]

    # Filter cookies to populate cache
    filtered = jar.filter_cookies(URL("http://example.com/"))
    assert "shared" in filtered
    assert filtered["shared"].value == "value"

    # Verify cache was populated
    assert ("", "") in jar._morsel_cache
    assert "shared" in jar._morsel_cache[("", "")]

    # Verify the cached morsel is the same one returned
    cached_morsel = jar._morsel_cache[("", "")]["shared"]
    assert cached_morsel is filtered["shared"]


async def test_shared_cookie_cache_clearing_on_update() -> None:
    """Test that shared cookie cache is cleared when cookie is updated."""
    jar = CookieJar(unsafe=True)

    # Create initial shared cookie
    sc = SimpleCookie()
    sc["shared"] = "value1"
    sc["shared"]["path"] = "/"
    jar.update_cookies(sc, URL())

    # Filter to populate cache
    filtered1 = jar.filter_cookies(URL("http://example.com/"))
    assert filtered1["shared"].value == "value1"
    assert "shared" in jar._morsel_cache[("", "")]

    # Update the cookie with new value
    sc2 = SimpleCookie()
    sc2["shared"] = "value2"
    sc2["shared"]["path"] = "/"
    jar.update_cookies(sc2, URL())

    # Verify cache was cleared
    assert "shared" not in jar._morsel_cache[("", "")]

    # Filter again to verify new value
    filtered2 = jar.filter_cookies(URL("http://example.com/"))
    assert filtered2["shared"].value == "value2"

    # Verify cache was repopulated with new value
    assert "shared" in jar._morsel_cache[("", "")]


async def test_shared_cookie_cache_clearing_on_delete() -> None:
    """Test that shared cookie cache is cleared when cookies are deleted."""
    jar = CookieJar(unsafe=True)

    # Create multiple shared cookies
    sc = SimpleCookie()
    sc["shared1"] = "value1"
    sc["shared1"]["path"] = "/"
    sc["shared2"] = "value2"
    sc["shared2"]["path"] = "/"
    jar.update_cookies(sc, URL())

    # Filter to populate cache
    jar.filter_cookies(URL("http://example.com/"))
    assert "shared1" in jar._morsel_cache[("", "")]
    assert "shared2" in jar._morsel_cache[("", "")]

    # Delete one cookie using internal method
    jar._delete_cookies([("", "", "shared1")])

    # Verify cookie and its cache entry were removed
    assert "shared1" not in jar._cookies[("", "")]
    assert "shared1" not in jar._morsel_cache[("", "")]

    # Verify other cookie remains
    assert "shared2" in jar._cookies[("", "")]
    assert "shared2" in jar._morsel_cache[("", "")]


async def test_shared_cookie_cache_clearing_on_clear() -> None:
    """Test that shared cookie cache is cleared when jar is cleared."""
    jar = CookieJar(unsafe=True)

    # Create shared and domain-specific cookies
    # Shared cookie
    sc1 = SimpleCookie()
    sc1["shared"] = "shared_value"
    sc1["shared"]["path"] = "/"
    jar.update_cookies(sc1, URL())

    # Domain-specific cookie
    sc2 = SimpleCookie()
    sc2["domain_cookie"] = "domain_value"
    jar.update_cookies(sc2, URL("http://example.com/"))

    # Filter to populate caches
    jar.filter_cookies(URL("http://example.com/"))

    # Verify caches are populated
    assert ("", "") in jar._morsel_cache
    assert "shared" in jar._morsel_cache[("", "")]
    assert ("example.com", "") in jar._morsel_cache
    assert "domain_cookie" in jar._morsel_cache[("example.com", "")]

    # Clear all cookies
    jar.clear()

    # Verify all caches are cleared
    assert len(jar._morsel_cache) == 0
    assert len(jar._cookies) == 0

    # Verify filtering returns no cookies
    filtered = jar.filter_cookies(URL("http://example.com/"))
    assert len(filtered) == 0


async def test_shared_cookie_with_multiple_domains() -> None:
    """Test that shared cookies work across different domains."""
    jar = CookieJar(unsafe=True)

    # Create a truly shared cookie
    sc = SimpleCookie()
    sc["universal"] = "everywhere"
    sc["universal"]["path"] = "/"
    jar.update_cookies(sc, URL())

    # Test filtering for different domains
    domains = [
        "http://example.com/",
        "http://test.org/",
        "http://localhost/",
        "http://192.168.1.1/",  # IP address (requires unsafe=True)
    ]

    for domain_url in domains:
        filtered = jar.filter_cookies(URL(domain_url))
        assert "universal" in filtered
        assert filtered["universal"].value == "everywhere"

    # Verify cache is reused efficiently
    assert ("", "") in jar._morsel_cache
    assert "universal" in jar._morsel_cache[("", "")]
