import asyncio
import datetime
import unittest
from http.cookies import SimpleCookie
from unittest import mock

import pytest

from aiohttp import CookieJar


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
        "path1-cookie=nineth; Domain=pathtest.com; Path=/; "
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
        "wrong-path-cookie=nineth; Domain=pathtest.com; Path=somepath;"
    )


def test_date_parsing():
    parse_func = CookieJar._parse_date
    utc = datetime.timezone.utc

    assert parse_func("") is None

    # 70 -> 1970
    assert parse_func("Tue, 1 Jan 70 00:00:00 GMT") == \
        datetime.datetime(1970, 1, 1, tzinfo=utc)

    # 10 -> 2010
    assert parse_func("Tue, 1 Jan 10 00:00:00 GMT") == \
        datetime.datetime(2010, 1, 1, tzinfo=utc)

    # No day of week string
    assert parse_func("1 Jan 1970 00:00:00 GMT") == \
        datetime.datetime(1970, 1, 1, tzinfo=utc)

    # No timezone string
    assert parse_func("Tue, 1 Jan 1970 00:00:00") == \
        datetime.datetime(1970, 1, 1, tzinfo=utc)

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


def test_domain_matching():
    test_func = CookieJar._is_domain_match

    assert test_func("test.com", "test.com")
    assert test_func("test.com", "sub.test.com")

    assert not test_func("test.com", "")
    assert not test_func("test.com", "test.org")
    assert not test_func("diff-test.com", "test.com")
    assert not test_func("test.com", "diff-test.com")
    assert not test_func("test.com", "127.0.0.1")


def test_path_matching():
    test_func = CookieJar._is_path_match

    assert test_func("/", "")
    assert test_func("", "/")
    assert test_func("/file", "")
    assert test_func("/folder/file", "")
    assert test_func("/", "/")
    assert test_func("/file", "/")
    assert test_func("/file", "/file")
    assert test_func("/folder/", "/folder/")
    assert test_func("/folder/", "/")
    assert test_func("/folder/file", "/")

    assert not test_func("/", "/file")
    assert not test_func("/", "/folder/")
    assert not test_func("/file", "/folder/file")
    assert not test_func("/folder/", "/folder/file")
    assert not test_func("/different-file", "/file")
    assert not test_func("/different-folder/", "/folder/")


def test_constructor(loop, cookies_to_send, cookies_to_receive):
    jar = CookieJar(loop=loop)
    jar.update_cookies(cookies_to_send)
    jar_cookies = SimpleCookie()
    for cookie in jar:
        dict.__setitem__(jar_cookies, cookie.key, cookie)
    expected_cookies = cookies_to_send
    assert jar_cookies == expected_cookies
    assert jar._loop is loop


def test_ctor_ith_default_loop(loop):
    asyncio.set_event_loop(loop)
    jar = CookieJar()
    assert jar._loop is loop


def test_domain_filter_ip_cookie_send(loop):
    jar = CookieJar(loop=loop)
    cookies = SimpleCookie(
        "shared-cookie=first; "
        "domain-cookie=second; Domain=example.com; "
        "subdomain1-cookie=third; Domain=test1.example.com; "
        "subdomain2-cookie=fourth; Domain=test2.example.com; "
        "dotted-domain-cookie=fifth; Domain=.example.com; "
        "different-domain-cookie=sixth; Domain=different.org; "
        "secure-cookie=seventh; Domain=secure.com; Secure; "
        "no-path-cookie=eighth; Domain=pathtest.com; "
        "path1-cookie=nineth; Domain=pathtest.com; Path=/; "
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
    cookies_sent = jar.filter_cookies("http://1.2.3.4/").output(
        header='Cookie:')
    assert cookies_sent == 'Cookie: shared-cookie=first'


def test_domain_filter_ip_cookie_receive(loop, cookies_to_receive):
    jar = CookieJar(loop=loop)

    jar.update_cookies(cookies_to_receive, "http://1.2.3.4/")
    assert len(jar) == 0


def test_preserving_ip_domain_cookies(loop):
    jar = CookieJar(loop=loop, unsafe=True)
    jar.update_cookies(SimpleCookie(
        "shared-cookie=first; "
        "ip-cookie=second; Domain=127.0.0.1;"
    ))
    cookies_sent = jar.filter_cookies("http://127.0.0.1/").output(
        header='Cookie:')
    assert cookies_sent == ('Cookie: ip-cookie=second\r\n'
                            'Cookie: shared-cookie=first')


def test_ignore_domain_ending_with_dot(loop):
    jar = CookieJar(loop=loop, unsafe=True)
    jar.update_cookies(SimpleCookie("cookie=val; Domain=example.com.;"),
                       "http://www.example.com")
    cookies_sent = jar.filter_cookies("http://www.example.com/")
    assert cookies_sent.output(header='Cookie:') == "Cookie: cookie=val"
    cookies_sent = jar.filter_cookies("http://example.com/")
    assert cookies_sent.output(header='Cookie:') == ""


class TestCookieJarBase(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        # N.B. those need to be overriden in child test cases
        self.jar = CookieJar(loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def request_reply_with_same_url(self, url):
        self.jar.update_cookies(self.cookies_to_send)
        cookies_sent = self.jar.filter_cookies(url)

        self.jar.clear()

        self.jar.update_cookies(self.cookies_to_receive, url)
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
            "path1-cookie=nineth; Domain=pathtest.com; Path=/; "
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
            "wrong-path-cookie=nineth; Domain=pathtest.com; Path=somepath;"
        )

        self.jar = CookieJar(loop=self.loop)

    def timed_request(self, url, update_time, send_time):
        with mock.patch.object(self.loop, 'time', return_value=update_time):
            self.jar.update_cookies(self.cookies_to_send)

        with mock.patch.object(self.loop, 'time', return_value=send_time):
            cookies_sent = self.jar.filter_cookies(url)

        self.jar.clear()

        return cookies_sent

    def test_domain_filter_same_host(self):
        cookies_sent, cookies_received = (
            self.request_reply_with_same_url("http://example.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "domain-cookie",
            "dotted-domain-cookie"
        })

        self.assertEqual(set(cookies_received.keys()), {
            "unconstrained-cookie",
            "domain-cookie",
            "dotted-domain-cookie"
        })

    def test_domain_filter_same_host_and_subdomain(self):
        cookies_sent, cookies_received = (
            self.request_reply_with_same_url("http://test1.example.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "domain-cookie",
            "subdomain1-cookie",
            "dotted-domain-cookie"
        })

        self.assertEqual(set(cookies_received.keys()), {
            "unconstrained-cookie",
            "domain-cookie",
            "subdomain1-cookie",
            "dotted-domain-cookie"
        })

    def test_domain_filter_same_host_diff_subdomain(self):
        cookies_sent, cookies_received = (
            self.request_reply_with_same_url("http://different.example.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "domain-cookie",
            "dotted-domain-cookie"
        })

        self.assertEqual(set(cookies_received.keys()), {
            "unconstrained-cookie",
            "domain-cookie",
            "dotted-domain-cookie"
        })

    def test_domain_filter_diff_host(self):
        cookies_sent, cookies_received = (
            self.request_reply_with_same_url("http://different.org/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "different-domain-cookie"
        })

        self.assertEqual(set(cookies_received.keys()), {
            "unconstrained-cookie",
            "different-domain-cookie"
        })

    def test_domain_filter_host_only(self):
        self.jar.update_cookies(self.cookies_to_receive, "http://example.com/")

        cookies_sent = self.jar.filter_cookies("http://example.com/")
        self.assertIn("unconstrained-cookie", set(cookies_sent.keys()))

        cookies_sent = self.jar.filter_cookies("http://different.org/")
        self.assertNotIn("unconstrained-cookie", set(cookies_sent.keys()))

    def test_secure_filter(self):
        cookies_sent, _ = (
            self.request_reply_with_same_url("http://secure.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie"
        })

        cookies_sent, _ = (
            self.request_reply_with_same_url("https://secure.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "secure-cookie"
        })

    def test_path_filter_root(self):
        cookies_sent, _ = (
            self.request_reply_with_same_url("http://pathtest.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie"
        })

    def test_path_filter_folder(self):

        cookies_sent, _ = (
            self.request_reply_with_same_url("http://pathtest.com/one/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie"
        })

    def test_path_filter_file(self):

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two")

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
            "path3-cookie"
        })

    def test_path_filter_subfolder(self):

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two/")

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
            "path3-cookie",
            "path4-cookie"
        })

    def test_path_filter_subsubfolder(self):

        cookies_sent, _ = self.request_reply_with_same_url(
            "http://pathtest.com/one/two/three/")

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie",
            "path2-cookie",
            "path3-cookie",
            "path4-cookie"
        })

    def test_path_filter_different_folder(self):

        cookies_sent, _ = (
            self.request_reply_with_same_url("http://pathtest.com/hundred/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "no-path-cookie",
            "path1-cookie"
        })

    def test_path_value(self):
        _, cookies_received = (
            self.request_reply_with_same_url("http://pathtest.com/"))

        self.assertEqual(set(cookies_received.keys()), {
            "unconstrained-cookie",
            "no-path-cookie",
            "path-cookie",
            "wrong-path-cookie"
        })

        self.assertEqual(cookies_received["no-path-cookie"]["path"], "/")
        self.assertEqual(cookies_received["path-cookie"]["path"], "/somepath")
        self.assertEqual(cookies_received["wrong-path-cookie"]["path"], "/")

    def test_expires(self):
        ts_before = datetime.datetime(
            1975, 1, 1, tzinfo=datetime.timezone.utc).timestamp()

        ts_after = datetime.datetime(
            2115, 1, 1, tzinfo=datetime.timezone.utc).timestamp()

        cookies_sent = self.timed_request(
            "http://expirestest.com/", ts_before, ts_before)

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "expires-cookie"
        })

        cookies_sent = self.timed_request(
            "http://expirestest.com/", ts_before, ts_after)

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie"
        })

    def test_max_age(self):
        cookies_sent = self.timed_request(
            "http://maxagetest.com/", 1000, 1000)

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "max-age-cookie"
        })

        cookies_sent = self.timed_request(
            "http://maxagetest.com/", 1000, 2000)

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie"
        })

    def test_invalid_values(self):
        cookies_sent, cookies_received = (
            self.request_reply_with_same_url("http://invalid-values.com/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie",
            "invalid-max-age-cookie",
            "invalid-expires-cookie"
        })

        cookie = cookies_sent["invalid-max-age-cookie"]
        self.assertEqual(cookie["max-age"], "")

        cookie = cookies_sent["invalid-expires-cookie"]
        self.assertEqual(cookie["expires"], "")
