import asyncio
import pytest
import unittest
import datetime
import http.cookies
from unittest import mock
from aiohttp import helpers, test_utils


def test_parse_mimetype_1():
    assert helpers.parse_mimetype('') == ('', '', '', {})


def test_parse_mimetype_2():
    assert helpers.parse_mimetype('*') == ('*', '*', '', {})


def test_parse_mimetype_3():
    assert (helpers.parse_mimetype('application/json') ==
            ('application', 'json', '', {}))


def test_parse_mimetype_4():
    assert (
        helpers.parse_mimetype('application/json;  charset=utf-8') ==
        ('application', 'json', '', {'charset': 'utf-8'}))


def test_parse_mimetype_5():
    assert (
        helpers.parse_mimetype('''application/json; charset=utf-8;''') ==
        ('application', 'json', '', {'charset': 'utf-8'}))


def test_parse_mimetype_6():
    assert(
        helpers.parse_mimetype('ApPlIcAtIoN/JSON;ChaRseT="UTF-8"') ==
        ('application', 'json', '', {'charset': 'UTF-8'}))


def test_parse_mimetype_7():
    assert (
        helpers.parse_mimetype('application/rss+xml') ==
        ('application', 'rss', 'xml', {}))


def test_parse_mimetype_8():
    assert (
        helpers.parse_mimetype('text/plain;base64') ==
        ('text', 'plain', '', {'base64': ''}))


def test_basic_auth1():
    # missing password here
    with pytest.raises(ValueError):
        helpers.BasicAuth(None)


def test_basic_auth2():
    with pytest.raises(ValueError):
        helpers.BasicAuth('nkim', None)


def test_basic_auth3():
    auth = helpers.BasicAuth('nkim')
    assert auth.login == 'nkim'
    assert auth.password == ''


def test_basic_auth4():
    auth = helpers.BasicAuth('nkim', 'pwd')
    assert auth.login == 'nkim'
    assert auth.password == 'pwd'
    assert auth.encode() == 'Basic bmtpbTpwd2Q='


def test_basic_auth_decode():
    auth = helpers.BasicAuth.decode('Basic bmtpbTpwd2Q=')
    assert auth.login == 'nkim'
    assert auth.password == 'pwd'


def test_basic_auth_invalid():
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode('bmtpbTpwd2Q=')


def test_basic_auth_decode_not_basic():
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode('Complex bmtpbTpwd2Q=')


def test_basic_auth_decode_bad_base64():
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode('Basic bmtpbTpwd2Q')


def test_invalid_formdata_params():
    with pytest.raises(TypeError):
        helpers.FormData('asdasf')


def test_invalid_formdata_params2():
    with pytest.raises(TypeError):
        helpers.FormData('as')  # 2-char str is not allowed


def test_invalid_formdata_content_type():
    form = helpers.FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo', 'bar', content_type=invalid_val)


def test_invalid_formdata_filename():
    form = helpers.FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo', 'bar', filename=invalid_val)


def test_invalid_formdata_content_transfer_encoding():
    form = helpers.FormData()
    invalid_vals = [0, 0.1, {}, [], b'foo']
    for invalid_val in invalid_vals:
        with pytest.raises(TypeError):
            form.add_field('foo',
                           'bar',
                           content_transfer_encoding=invalid_val)


def test_access_logger_format():
    log_format = '%T {%{SPAM}e} "%{ETag}o" %X {X} %%P'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    expected = '%s {%s} "%s" %%X {X} %%%s'
    assert expected == access_logger._log_format


@mock.patch("aiohttp.helpers.datetime")
@mock.patch("os.getpid")
def test_access_logger_atoms(mock_getpid, mock_datetime):
    utcnow = datetime.datetime(1843, 1, 1, 0, 0)
    mock_datetime.datetime.utcnow.return_value = utcnow
    mock_getpid.return_value = 42
    log_format = '%a %t %P %l %u %r %s %b %O %T %Tf %D'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    message = mock.Mock(headers={}, method="GET", path="/path", version=(1, 1))
    environ = {}
    response = mock.Mock(headers={}, output_length=123,
                         body_length=42, status=200)
    transport = mock.Mock()
    transport.get_extra_info.return_value = ("127.0.0.2", 1234)
    access_logger.log(message, environ, response, transport, 3.1415926)
    assert not mock_logger.exception.called
    expected = ('127.0.0.2 [01/Jan/1843:00:00:00 +0000] <42> - - '
                'GET /path HTTP/1.1 200 42 123 3 3.141593 3141593')
    mock_logger.info.assert_called_with(expected)


def test_access_logger_dicts():
    log_format = '%{User-Agent}i %{Content-Length}o %{SPAM}e %{None}i'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    message = mock.Mock(headers={"USER-AGENT": "Mock/1.0"}, version=(1, 1))
    environ = {"SPAM": "EGGS"}
    response = mock.Mock(headers={"CONTENT-LENGTH": 123})
    transport = mock.Mock()
    transport.get_extra_info.return_value = ("127.0.0.2", 1234)
    access_logger.log(message, environ, response, transport, 0.0)
    assert not mock_logger.error.called
    expected = 'Mock/1.0 123 EGGS -'
    mock_logger.info.assert_called_with(expected)


def test_logger_no_message_and_environ():
    mock_logger = mock.Mock()
    mock_transport = mock.Mock()
    mock_transport.get_extra_info.return_value = ("127.0.0.3", 0)
    access_logger = helpers.AccessLogger(mock_logger,
                                         "%r %{FOOBAR}e %{content-type}i")
    access_logger.log(None, None, None, mock_transport, 0.0)
    mock_logger.info.assert_called_with("- - (no headers)")


def test_reify():
    class A:
        @helpers.reify
        def prop(self):
            return 1

    a = A()
    assert 1 == a.prop


def test_reify_class():
    class A:
        @helpers.reify
        def prop(self):
            """Docstring."""
            return 1

    assert isinstance(A.prop, helpers.reify)
    assert 'Docstring.' == A.prop.__doc__


def test_reify_assignment():
    class A:
        @helpers.reify
        def prop(self):
            return 1

    a = A()

    with pytest.raises(AttributeError):
        a.prop = 123


def test_requote_uri_with_unquoted_percents():
    # Ensure we handle unquoted percent signs in redirects.
    bad_uri = 'http://example.com/fiz?buz=%ppicture'
    quoted = 'http://example.com/fiz?buz=%25ppicture'
    assert quoted == helpers.requote_uri(bad_uri)


def test_requote_uri_properly_requotes():
    # Ensure requoting doesn't break expectations.
    quoted = 'http://example.com/fiz?buz=%25ppicture'
    assert quoted == helpers.requote_uri(quoted)


def test_create_future_with_new_loop():
    # We should use the new create_future() if it's available.
    mock_loop = mock.Mock()
    expected = 'hello'
    mock_loop.create_future.return_value = expected
    assert expected == helpers.create_future(mock_loop)


@mock.patch('asyncio.Future')
def test_create_future_with_old_loop(MockFuture):
    # The old loop (without create_future()) should just have a Future object
    # wrapped around it.
    mock_loop = mock.Mock()
    del mock_loop.create_future

    expected = 'hello'
    MockFuture.return_value = expected

    future = helpers.create_future(mock_loop)
    MockFuture.assert_called_with(loop=mock_loop)
    assert expected == future


def test_is_ip_address():
    assert helpers.is_ip_address("127.0.0.1")
    assert helpers.is_ip_address("::1")
    assert helpers.is_ip_address("FE80:0000:0000:0000:0202:B3FF:FE1E:8329")

    # Hostnames
    assert not helpers.is_ip_address("localhost")
    assert not helpers.is_ip_address("www.example.com")

    # Out of range
    assert not helpers.is_ip_address("999.999.999.999")
    # Contain a port
    assert not helpers.is_ip_address("127.0.0.1:80")
    assert not helpers.is_ip_address("[2001:db8:0:1]:80")
    # Too many "::"
    assert not helpers.is_ip_address("1200::AB00:1234::2552:7777:1313")


class TestCookieJar(unittest.TestCase):

    def setUp(self):
        # Cookies to send from client to server as "Cookie" header
        self.cookies_to_send = http.cookies.SimpleCookie(
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

        # Cookies received from the server as "Set-Cookie" header
        self.cookies_to_receive = http.cookies.SimpleCookie(
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

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.jar = helpers.CookieJar(loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def request_reply_with_same_url(self, url):
        self.jar.update_cookies(self.cookies_to_send)
        cookies_sent = self.jar.filter_cookies(url)

        self.jar.cookies.clear()

        self.jar.update_cookies(self.cookies_to_receive, url)
        cookies_received = self.jar.cookies.copy()

        self.jar.cookies.clear()

        return cookies_sent, cookies_received

    def timed_request(
            self, url, update_time, send_time):
        time_func = "time.monotonic"

        with mock.patch(time_func, return_value=update_time):
            self.jar.update_cookies(self.cookies_to_send)

        with mock.patch(time_func, return_value=send_time):
            test_utils.run_briefly(self.loop)

            cookies_sent = self.jar.filter_cookies(url)

        self.jar.cookies.clear()

        return cookies_sent

    def test_constructor(self):
        jar = helpers.CookieJar(loop=self.loop)
        jar.update_cookies(self.cookies_to_send)
        self.assertEqual(jar.cookies, self.cookies_to_send)
        self.assertIs(jar._loop, self.loop)

    def test_domain_filter_ip(self):
        cookies_sent, cookies_received = (
            self.request_reply_with_same_url("http://1.2.3.4/"))

        self.assertEqual(set(cookies_sent.keys()), {
            "shared-cookie"
        })

        self.assertEqual(set(cookies_received.keys()), set())

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
            1985, 1, 1, tzinfo=datetime.timezone.utc).timestamp()

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

    def test_domain_matching(self):
        test_func = helpers.CookieJar._is_domain_match

        self.assertTrue(test_func("test.com", "test.com"))
        self.assertTrue(test_func("test.com", "sub.test.com"))

        self.assertFalse(test_func("test.com", ""))
        self.assertFalse(test_func("test.com", "test.org"))
        self.assertFalse(test_func("diff-test.com", "test.com"))
        self.assertFalse(test_func("test.com", "diff-test.com"))
        self.assertFalse(test_func("test.com", "127.0.0.1"))

    def test_path_matching(self):
        test_func = helpers.CookieJar._is_path_match

        self.assertTrue(test_func("/", ""))
        self.assertTrue(test_func("/file", ""))
        self.assertTrue(test_func("/folder/file", ""))
        self.assertTrue(test_func("/", "/"))
        self.assertTrue(test_func("/file", "/"))
        self.assertTrue(test_func("/file", "/file"))
        self.assertTrue(test_func("/folder/", "/folder/"))
        self.assertTrue(test_func("/folder/", "/"))
        self.assertTrue(test_func("/folder/file", "/"))

        self.assertFalse(test_func("/", "/file"))
        self.assertFalse(test_func("/", "/folder/"))
        self.assertFalse(test_func("/file", "/folder/file"))
        self.assertFalse(test_func("/folder/", "/folder/file"))
        self.assertFalse(test_func("/different-file", "/file"))
        self.assertFalse(test_func("/different-folder/", "/folder/"))

    def test_date_parsing(self):
        parse_func = helpers.CookieJar._parse_date
        utc = datetime.timezone.utc

        self.assertEqual(parse_func(""), None)

        # 70 -> 1970
        self.assertEqual(
            parse_func("Tue, 1 Jan 70 00:00:00 GMT"),
            datetime.datetime(1970, 1, 1, tzinfo=utc))

        # 10 -> 2010
        self.assertEqual(
            parse_func("Tue, 1 Jan 10 00:00:00 GMT"),
            datetime.datetime(2010, 1, 1, tzinfo=utc))

        # No day of week string
        self.assertEqual(
            parse_func("1 Jan 1970 00:00:00 GMT"),
            datetime.datetime(1970, 1, 1, tzinfo=utc))

        # No timezone string
        self.assertEqual(
            parse_func("Tue, 1 Jan 1970 00:00:00"),
            datetime.datetime(1970, 1, 1, tzinfo=utc))

        # No year
        self.assertEqual(parse_func("Tue, 1 Jan 00:00:00 GMT"), None)

        # No month
        self.assertEqual(parse_func("Tue, 1 1970 00:00:00 GMT"), None)

        # No day of month
        self.assertEqual(parse_func("Tue, Jan 1970 00:00:00 GMT"), None)

        # No time
        self.assertEqual(parse_func("Tue, 1 Jan 1970 GMT"), None)

        # Invalid day of month
        self.assertEqual(parse_func("Tue, 0 Jan 1970 00:00:00 GMT"), None)

        # Invalid year
        self.assertEqual(parse_func("Tue, 1 Jan 1500 00:00:00 GMT"), None)

        # Invalid time
        self.assertEqual(parse_func("Tue, 1 Jan 1970 77:88:99 GMT"), None)
