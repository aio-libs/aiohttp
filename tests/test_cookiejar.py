import asyncio
import datetime
import heapq
import itertools
import pathlib
import pickle
import unittest
from http.cookies import BaseCookie, Morsel, SimpleCookie
from operator import not_
from unittest import mock

import pytest
from freezegun import freeze_time
from yarl import URL

from aiohttp import CookieJar, DummyCookieJar


def dump_cookiejar() -> bytes:  # pragma: no cover
    """Create pickled data for test_pickle_format()."""
    cj = CookieJar()
    cj.update_cookies(cookies_to_send.__pytest_wrapped__.obj())
    return pickle.dumps(cj._cookies, pickle.HIGHEST_PROTOCOL)


@pytest.fixture
def cookies_to_send():
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
def cookies_to_send_with_expired():
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
def cookies_to_receive():
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


async def test_constructor(loop, cookies_to_send, cookies_to_receive) -> None:
    jar = CookieJar(loop=loop)
    jar.update_cookies(cookies_to_send)
    jar_cookies = SimpleCookie()
    for cookie in jar:
        dict.__setitem__(jar_cookies, cookie.key, cookie)
    expected_cookies = cookies_to_send
    assert jar_cookies == expected_cookies
    assert jar._loop is loop


async def test_constructor_with_expired(
    loop, cookies_to_send_with_expired, cookies_to_receive
) -> None:
    jar = CookieJar()
    jar.update_cookies(cookies_to_send_with_expired)
    jar_cookies = SimpleCookie()
    for cookie in jar:
        dict.__setitem__(jar_cookies, cookie.key, cookie)
    expected_cookies = cookies_to_send_with_expired
    assert jar_cookies != expected_cookies
    assert jar._loop is loop


async def test_save_load(tmp_path, loop, cookies_to_send, cookies_to_receive) -> None:
    file_path = pathlib.Path(str(tmp_path)) / "aiohttp.test.cookie"

    # export cookie jar
    jar_save = CookieJar(loop=loop)
    jar_save.update_cookies(cookies_to_receive)
    jar_save.save(file_path=file_path)

    jar_load = CookieJar(loop=loop)
    jar_load.load(file_path=file_path)

    jar_test = SimpleCookie()
    for cookie in jar_load:
        jar_test[cookie.key] = cookie

    assert jar_test == cookies_to_receive


async def test_update_cookie_with_unicode_domain(loop) -> None:
    cookies = (
        "idna-domain-first=first; Domain=xn--9caa.com; Path=/;",
        "idna-domain-second=second; Domain=xn--9caa.com; Path=/;",
    )

    jar = CookieJar(loop=loop)
    jar.update_cookies(SimpleCookie(cookies[0]), URL("http://éé.com/"))
    jar.update_cookies(SimpleCookie(cookies[1]), URL("http://xn--9caa.com/"))

    jar_test = SimpleCookie()
    for cookie in jar:
        jar_test[cookie.key] = cookie

    assert jar_test == SimpleCookie(" ".join(cookies))


async def test_filter_cookie_with_unicode_domain(loop) -> None:
    jar = CookieJar()
    jar.update_cookies(
        SimpleCookie("idna-domain-first=first; Domain=xn--9caa.com; Path=/; ")
    )
    assert len(jar.filter_cookies(URL("http://éé.com"))) == 1
    assert len(jar.filter_cookies(URL("http://xn--9caa.com"))) == 1


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
    loop,
    url,
    expected_cookies,
) -> None:
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


async def test_domain_filter_ip_cookie_receive(cookies_to_receive) -> None:
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
    ],
    ids=(
        "IP domain preserved",
        "no shared cookie",
        "quoted cookie with special char",
        "quoted cookie w/o special char",
        "unquoted cookie with special char",
    ),
)
async def test_quotes_correctly_based_on_input(
    loop, cookies, expected, quote_bool
) -> None:
    jar = CookieJar(unsafe=True, quote_cookie=quote_bool)
    jar.update_cookies(SimpleCookie(cookies))
    cookies_sent = jar.filter_cookies(URL("http://127.0.0.1/")).output(header="Cookie:")
    assert cookies_sent == expected


async def test_ignore_domain_ending_with_dot(loop) -> None:
    jar = CookieJar(loop=loop, unsafe=True)
    jar.update_cookies(
        SimpleCookie("cookie=val; Domain=example.com.;"), URL("http://www.example.com")
    )
    cookies_sent = jar.filter_cookies(URL("http://www.example.com/"))
    assert cookies_sent.output(header="Cookie:") == "Cookie: cookie=val"
    cookies_sent = jar.filter_cookies(URL("http://example.com/"))
    assert cookies_sent.output(header="Cookie:") == ""


class TestCookieJarBase(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        # N.B. those need to be overridden in child test cases
        async def make_jar():
            return CookieJar()

        self.jar = self.loop.run_until_complete(make_jar())

    def tearDown(self):
        self.loop.close()

    def request_reply_with_same_url(self, url):
        self.jar.update_cookies(self.cookies_to_send)
        cookies_sent = self.jar.filter_cookies(URL(url))

        self.jar.clear()

        self.jar.update_cookies(self.cookies_to_receive, URL(url))
        cookies_received = SimpleCookie()
        for cookie in self.jar:
            dict.__setitem__(cookies_received, cookie.key, cookie)

        self.jar.clear()

        return cookies_sent, cookies_received


class TestCookieJarSafe(TestCookieJarBase):
    def setUp(self):
        super().setUp()

        self.cookies_to_send = SimpleCookie(
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

        self.cookies_to_receive = SimpleCookie(
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

        async def make_jar():
            return CookieJar()

        self.jar = self.loop.run_until_complete(make_jar())

    def timed_request(self, url, update_time, send_time):
        if isinstance(update_time, int):
            update_time = datetime.timedelta(seconds=update_time)
        elif isinstance(update_time, float):
            update_time = datetime.datetime.fromtimestamp(update_time)
        if isinstance(send_time, int):
            send_time = datetime.timedelta(seconds=send_time)
        elif isinstance(send_time, float):
            send_time = datetime.datetime.fromtimestamp(send_time)

        with freeze_time(update_time):
            self.jar.update_cookies(self.cookies_to_send)

        with freeze_time(send_time):
            cookies_sent = self.jar.filter_cookies(URL(url))

        self.jar.clear()

        return cookies_sent

    def test_domain_filter_same_host(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://example.com/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {"shared-cookie", "domain-cookie", "dotted-domain-cookie"},
        )

        self.assertEqual(
            set(cookies_received.keys()),
            {"unconstrained-cookie", "domain-cookie", "dotted-domain-cookie"},
        )

    def test_domain_filter_same_host_and_subdomain(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://test1.example.com/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {
                "shared-cookie",
                "domain-cookie",
                "subdomain1-cookie",
                "dotted-domain-cookie",
            },
        )

        self.assertEqual(
            set(cookies_received.keys()),
            {
                "unconstrained-cookie",
                "domain-cookie",
                "subdomain1-cookie",
                "dotted-domain-cookie",
            },
        )

    def test_domain_filter_same_host_diff_subdomain(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://different.example.com/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {"shared-cookie", "domain-cookie", "dotted-domain-cookie"},
        )

        self.assertEqual(
            set(cookies_received.keys()),
            {"unconstrained-cookie", "domain-cookie", "dotted-domain-cookie"},
        )

    def test_domain_filter_diff_host(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://different.org/"
        )

        self.assertEqual(
            set(cookies_sent.keys()), {"shared-cookie", "different-domain-cookie"}
        )

        self.assertEqual(
            set(cookies_received.keys()),
            {"unconstrained-cookie", "different-domain-cookie"},
        )

    def test_domain_filter_host_only(self) -> None:
        self.jar.update_cookies(self.cookies_to_receive, URL("http://example.com/"))
        sub_cookie = SimpleCookie("subdomain=spam; Path=/;")
        self.jar.update_cookies(sub_cookie, URL("http://foo.example.com/"))

        cookies_sent = self.jar.filter_cookies(URL("http://foo.example.com/"))
        self.assertIn("subdomain", set(cookies_sent.keys()))
        self.assertNotIn("unconstrained-cookie", set(cookies_sent.keys()))

    def test_secure_filter(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url("http://secure.com/")

        self.assertEqual(set(cookies_sent.keys()), {"shared-cookie"})

        cookies_sent, _ = self.request_reply_with_same_url("https://secure.com/")

        self.assertEqual(set(cookies_sent.keys()), {"shared-cookie", "secure-cookie"})

    def test_path_filter_root(self) -> None:
        cookies_sent, _ = self.request_reply_with_same_url("http://pathtest.com/")

        self.assertEqual(
            set(cookies_sent.keys()),
            {"shared-cookie", "no-path-cookie", "path1-cookie"},
        )

    def test_path_filter_folder(self) -> None:

        cookies_sent, _ = self.request_reply_with_same_url("http://pathtest.com/one/")

        self.assertEqual(
            set(cookies_sent.keys()),
            {"shared-cookie", "no-path-cookie", "path1-cookie", "path2-cookie"},
        )

    def test_path_filter_file(self) -> None:

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {
                "shared-cookie",
                "no-path-cookie",
                "path1-cookie",
                "path2-cookie",
                "path3-cookie",
            },
        )

    def test_path_filter_subfolder(self) -> None:

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {
                "shared-cookie",
                "no-path-cookie",
                "path1-cookie",
                "path2-cookie",
                "path3-cookie",
                "path4-cookie",
            },
        )

    def test_path_filter_subsubfolder(self) -> None:

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two/three/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {
                "shared-cookie",
                "no-path-cookie",
                "path1-cookie",
                "path2-cookie",
                "path3-cookie",
                "path4-cookie",
            },
        )

    def test_path_filter_different_folder(self) -> None:

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/hundred/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {"shared-cookie", "no-path-cookie", "path1-cookie"},
        )

    def test_path_value(self) -> None:
        _, cookies_received = self.request_reply_with_same_url("http://pathtest.com/")

        self.assertEqual(
            set(cookies_received.keys()),
            {
                "unconstrained-cookie",
                "no-path-cookie",
                "path-cookie",
                "wrong-path-cookie",
            },
        )

        self.assertEqual(cookies_received["no-path-cookie"]["path"], "/")
        self.assertEqual(cookies_received["path-cookie"]["path"], "/somepath")
        self.assertEqual(cookies_received["wrong-path-cookie"]["path"], "/")

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

        self.assertEqual(set(cookies_sent.keys()), {"shared-cookie", "expires-cookie"})

        cookies_sent = self.timed_request(
            "http://expirestest.com/", ts_before, ts_after
        )

        self.assertEqual(set(cookies_sent.keys()), {"shared-cookie"})

    def test_max_age(self) -> None:
        cookies_sent = self.timed_request("http://maxagetest.com/", 1000, 1000)

        self.assertEqual(set(cookies_sent.keys()), {"shared-cookie", "max-age-cookie"})

        cookies_sent = self.timed_request("http://maxagetest.com/", 1000, 2000)

        self.assertEqual(set(cookies_sent.keys()), {"shared-cookie"})

    def test_invalid_values(self) -> None:
        cookies_sent, cookies_received = self.request_reply_with_same_url(
            "http://invalid-values.com/"
        )

        self.assertEqual(
            set(cookies_sent.keys()),
            {"shared-cookie", "invalid-max-age-cookie", "invalid-expires-cookie"},
        )

        cookie = cookies_sent["invalid-max-age-cookie"]
        self.assertEqual(cookie["max-age"], "")

        cookie = cookies_sent["invalid-expires-cookie"]
        self.assertEqual(cookie["expires"], "")

    def test_cookie_not_expired_when_added_after_removal(self) -> None:
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

        async def make_jar():
            return CookieJar(unsafe=True)

        jar = self.loop.run_until_complete(make_jar())
        # Remove `foo` cookie.
        jar.update_cookies(SimpleCookie('foo=""; Max-Age=0'))
        # Set `foo` cookie to `bar`.
        jar.update_cookies(SimpleCookie('foo="bar"'))

        # Assert that there is a cookie.
        assert len(jar) == 1

    def test_path_filter_diff_folder_same_name(self) -> None:
        async def make_jar():
            return CookieJar(unsafe=True)

        jar = self.loop.run_until_complete(make_jar())

        jar.update_cookies(
            SimpleCookie("path-cookie=zero; Domain=pathtest.com; Path=/; ")
        )
        jar.update_cookies(
            SimpleCookie("path-cookie=one; Domain=pathtest.com; Path=/one; ")
        )
        self.assertEqual(len(jar), 2)

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/"))
        self.assertEqual(len(jar_filtered), 1)
        self.assertEqual(jar_filtered["path-cookie"].value, "zero")

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/one"))
        self.assertEqual(len(jar_filtered), 1)
        self.assertEqual(jar_filtered["path-cookie"].value, "one")

    def test_path_filter_diff_folder_same_name_return_best_match_independent_from_put_order(
        self,
    ) -> None:
        async def make_jar():
            return CookieJar(unsafe=True)

        jar = self.loop.run_until_complete(make_jar())
        jar.update_cookies(
            SimpleCookie("path-cookie=one; Domain=pathtest.com; Path=/one; ")
        )
        jar.update_cookies(
            SimpleCookie("path-cookie=zero; Domain=pathtest.com; Path=/; ")
        )
        jar.update_cookies(
            SimpleCookie("path-cookie=two; Domain=pathtest.com; Path=/second; ")
        )
        self.assertEqual(len(jar), 3)

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/"))
        self.assertEqual(len(jar_filtered), 1)
        self.assertEqual(jar_filtered["path-cookie"].value, "zero")

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/second"))
        self.assertEqual(len(jar_filtered), 1)
        self.assertEqual(jar_filtered["path-cookie"].value, "two")

        jar_filtered = jar.filter_cookies(URL("http://pathtest.com/one"))
        self.assertEqual(len(jar_filtered), 1)
        self.assertEqual(jar_filtered["path-cookie"].value, "one")


async def test_dummy_cookie_jar() -> None:
    cookie = SimpleCookie("foo=bar; Domain=example.com;")
    dummy_jar = DummyCookieJar()
    assert len(dummy_jar) == 0
    dummy_jar.update_cookies(cookie)
    assert len(dummy_jar) == 0
    with pytest.raises(StopIteration):
        next(iter(dummy_jar))
    assert not dummy_jar.filter_cookies(URL("http://example.com/"))
    dummy_jar.clear()


async def test_loose_cookies_types() -> None:
    jar = CookieJar()

    accepted_types = [
        [("str", BaseCookie())],
        [("str", Morsel())],
        [
            ("str", "str"),
        ],
        {"str": BaseCookie()},
        {"str": Morsel()},
        {"str": "str"},
        SimpleCookie(),
    ]

    for loose_cookies_type in accepted_types:
        jar.update_cookies(cookies=loose_cookies_type)


async def test_cookie_jar_clear_all():
    sut = CookieJar()
    cookie = SimpleCookie()
    cookie["foo"] = "bar"
    sut.update_cookies(cookie)

    sut.clear()
    assert len(sut) == 0


async def test_cookie_jar_clear_expired():
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


async def test_pickle_format(cookies_to_send) -> None:
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
async def test_treat_as_secure_origin_init(url) -> None:
    jar = CookieJar(unsafe=True, treat_as_secure_origin=url)
    assert jar._treat_as_secure_origin == [URL("http://127.0.0.1")]


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
