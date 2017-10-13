import asyncio
import datetime
import gc
import os
import sys
import tempfile
from unittest import mock

import pytest
from yarl import URL

from aiohttp import helpers
from aiohttp.abc import AbstractAccessLogger


# -------------------- coro guard --------------------------------


@asyncio.coroutine
def test_warn():
    with pytest.warns(DeprecationWarning) as ctx:
        helpers.deprecated_noop('Text')

    w = ctx.list[0]

    assert str(w.message) == 'Text'
    # Assert the warning points at us and not at _CoroGuard.
    assert w.filename == __file__


@asyncio.coroutine
def test_no_warn_on_await():
    with pytest.warns(None) as ctx:
        yield from helpers.deprecated_noop('Text')
    assert not ctx.list


def test_coro_guard_close():
    guard = helpers.deprecated_noop('Text')
    guard.close()
    assert not guard.gi_running


# ------------------- parse_mimetype ----------------------------------

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


# ------------------- guess_filename ----------------------------------

def test_guess_filename_with_tempfile():
    with tempfile.TemporaryFile() as fp:
        assert (helpers.guess_filename(fp, 'no-throw') is not None)


# ------------------- BasicAuth -----------------------------------

def test_basic_auth1():
    # missing password here
    with pytest.raises(ValueError):
        helpers.BasicAuth(None)


def test_basic_auth2():
    with pytest.raises(ValueError):
        helpers.BasicAuth('nkim', None)


def test_basic_with_auth_colon_in_login():
    with pytest.raises(ValueError):
        helpers.BasicAuth('nkim:1', 'pwd')


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


def test_basic_auth_from_url():
    url = URL('http://user:pass@example.com')
    auth = helpers.BasicAuth.from_url(url)
    assert auth.login == 'user'
    assert auth.password == 'pass'


def test_basic_auth_from_not_url():
    with pytest.raises(TypeError):
        helpers.BasicAuth.from_url('http://user:pass@example.com')


# ------------- access logger -------------------------


def test_access_logger_format():
    log_format = '%T "%{ETag}o" %X {X} %%P'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    expected = '%s "%s" %%X {X} %%%s'
    assert expected == access_logger._log_format


def test_access_logger_atoms(mocker):
    mock_datetime = mocker.patch("aiohttp.helpers.datetime")
    mock_getpid = mocker.patch("os.getpid")
    utcnow = datetime.datetime(1843, 1, 1, 0, 0)
    mock_datetime.datetime.utcnow.return_value = utcnow
    mock_getpid.return_value = 42
    log_format = '%a %t %P %l %u %r %s %b %T %Tf %D'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    request = mock.Mock(headers={}, method="GET", path_qs="/path",
                        version=(1, 1),
                        remote="127.0.0.2")
    response = mock.Mock(headers={}, body_length=42, status=200)
    access_logger.log(request, response, 3.1415926)
    assert not mock_logger.exception.called
    expected = ('127.0.0.2 [01/Jan/1843:00:00:00 +0000] <42> - - '
                'GET /path HTTP/1.1 200 42 3 3.141593 3141593')
    extra = {
        'first_request_line': 'GET /path HTTP/1.1',
        'process_id': '<42>',
        'remote_address': '127.0.0.2',
        'request_time': 3,
        'request_time_frac': '3.141593',
        'request_time_micro': 3141593,
        'response_size': 42,
        'response_status': 200
    }

    mock_logger.info.assert_called_with(expected, extra=extra)


def test_access_logger_dicts():
    log_format = '%{User-Agent}i %{Content-Length}o %{None}i'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    request = mock.Mock(headers={"User-Agent": "Mock/1.0"}, version=(1, 1),
                        remote="127.0.0.2")
    response = mock.Mock(headers={"Content-Length": 123})
    access_logger.log(request, response, 0.0)
    assert not mock_logger.error.called
    expected = 'Mock/1.0 123 -'
    extra = {
        'request_header': {'None': '-'},
        'response_header': {'Content-Length': 123}
    }

    mock_logger.info.assert_called_with(expected, extra=extra)


def test_access_logger_unix_socket():
    log_format = '|%a|'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    request = mock.Mock(headers={"User-Agent": "Mock/1.0"}, version=(1, 1),
                        remote="")
    response = mock.Mock()
    access_logger.log(request, response, 0.0)
    assert not mock_logger.error.called
    expected = '||'
    mock_logger.info.assert_called_with(expected, extra={'remote_address': ''})


def test_logger_no_message():
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger,
                                         "%r %{content-type}i")
    extra_dict = {
        'first_request_line': '-',
        'request_header': {'content-type': '(no headers)'}
    }

    access_logger.log(None, None, 0.0)
    mock_logger.info.assert_called_with("- (no headers)", extra=extra_dict)


def test_logger_internal_error():
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, "%D")
    access_logger.log(None, None, 'invalid')
    mock_logger.exception.assert_called_with("Error in logging")


def test_logger_no_transport():
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, "%a")
    access_logger.log(None, None, 0)
    mock_logger.info.assert_called_with("-", extra={'remote_address': '-'})


def test_logger_abc():
    class Logger(AbstractAccessLogger):
        def log(self, request, response, time):
            1 / 0

    mock_logger = mock.Mock()
    access_logger = Logger(mock_logger, None)

    with pytest.raises(ZeroDivisionError):
        access_logger.log(None, None, None)

    class Logger(AbstractAccessLogger):
        def log(self, request, response, time):
            self.logger.info(self.log_format.format(
                request=request,
                response=response,
                time=time
            ))

    mock_logger = mock.Mock()
    access_logger = Logger(mock_logger, '{request} {response} {time}')
    access_logger.log('request', 'response', 1)
    mock_logger.info.assert_called_with('request response 1')


class TestReify:

    def test_reify(self):
        class A:
            def __init__(self):
                self._cache = {}

            @helpers.reify
            def prop(self):
                return 1

        a = A()
        assert 1 == a.prop

    def test_reify_class(self):
        class A:
            def __init__(self):
                self._cache = {}

            @helpers.reify
            def prop(self):
                """Docstring."""
                return 1

        assert isinstance(A.prop, helpers.reify)
        assert 'Docstring.' == A.prop.__doc__

    def test_reify_assignment(self):
        class A:
            def __init__(self):
                self._cache = {}

            @helpers.reify
            def prop(self):
                return 1

        a = A()

        with pytest.raises(AttributeError):
            a.prop = 123


@pytest.mark.skipif(sys.version_info < (3, 5, 2), reason='old python')
def test_create_future_with_new_loop():
    # We should use the new create_future() if it's available.
    mock_loop = mock.Mock()
    expected = 'hello'
    mock_loop.create_future.return_value = expected
    assert expected == helpers.create_future(mock_loop)


@pytest.mark.skipif(sys.version_info >= (3, 5, 2), reason='new python')
def test_create_future_with_old_loop(mocker):
    MockFuture = mocker.patch('asyncio.Future')
    # The old loop (without create_future()) should just have a Future object
    # wrapped around it.
    mock_loop = mock.Mock()
    del mock_loop.create_future

    expected = 'hello'
    MockFuture.return_value = expected

    future = helpers.create_future(mock_loop)
    MockFuture.assert_called_with(loop=mock_loop)
    assert expected == future

# ----------------------------------- is_ip_address() ----------------------


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


def test_is_ip_address_bytes():
    assert helpers.is_ip_address(b"127.0.0.1")
    assert helpers.is_ip_address(b"::1")
    assert helpers.is_ip_address(b"FE80:0000:0000:0000:0202:B3FF:FE1E:8329")

    # Hostnames
    assert not helpers.is_ip_address(b"localhost")
    assert not helpers.is_ip_address(b"www.example.com")

    # Out of range
    assert not helpers.is_ip_address(b"999.999.999.999")
    # Contain a port
    assert not helpers.is_ip_address(b"127.0.0.1:80")
    assert not helpers.is_ip_address(b"[2001:db8:0:1]:80")
    # Too many "::"
    assert not helpers.is_ip_address(b"1200::AB00:1234::2552:7777:1313")


def test_ip_addresses():
    ip_addresses = [
        '0.0.0.0',
        '127.0.0.1',
        '255.255.255.255',
        '0:0:0:0:0:0:0:0',
        'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
        '00AB:0002:3008:8CFD:00AB:0002:3008:8CFD',
        '00ab:0002:3008:8cfd:00ab:0002:3008:8cfd',
        'AB:02:3008:8CFD:AB:02:3008:8CFD',
        'AB:02:3008:8CFD::02:3008:8CFD',
        '::',
        '1::1',
    ]
    for address in ip_addresses:
        assert helpers.is_ip_address(address)


def test_host_addresses():
    hosts = [
        'www.four.part.host'
        'www.python.org',
        'foo.bar',
        'localhost',
    ]
    for host in hosts:
        assert not helpers.is_ip_address(host)


def test_is_ip_address_invalid_type():
    with pytest.raises(TypeError):
        helpers.is_ip_address(123)

    with pytest.raises(TypeError):
        helpers.is_ip_address(object())


# ----------------------------------- TimeoutHandle -------------------

def test_timeout_handle(loop):
    handle = helpers.TimeoutHandle(loop, 10.2)
    cb = mock.Mock()
    handle.register(cb)
    assert cb == handle._callbacks[0][0]
    handle.close()
    assert not handle._callbacks


def test_timeout_handle_cb_exc(loop):
    handle = helpers.TimeoutHandle(loop, 10.2)
    cb = mock.Mock()
    handle.register(cb)
    cb.side_effect = ValueError()
    handle()
    assert cb.called
    assert not handle._callbacks


def test_timer_context_cancelled():
    with mock.patch('aiohttp.helpers.asyncio') as m_asyncio:
        m_asyncio.TimeoutError = asyncio.TimeoutError
        loop = mock.Mock()
        ctx = helpers.TimerContext(loop)
        ctx.timeout()

        with pytest.raises(asyncio.TimeoutError):
            with ctx:
                pass

        assert m_asyncio.Task.current_task.return_value.cancel.called


def test_timer_context_no_task(loop):
    with pytest.raises(RuntimeError):
        with helpers.TimerContext(loop):
            pass


# -------------------------------- CeilTimeout --------------------------


@asyncio.coroutine
def test_weakref_handle(loop):
    cb = mock.Mock()
    helpers.weakref_handle(cb, 'test', 0.01, loop, False)
    yield from asyncio.sleep(0.1, loop=loop)
    assert cb.test.called


@asyncio.coroutine
def test_weakref_handle_weak(loop):
    cb = mock.Mock()
    helpers.weakref_handle(cb, 'test', 0.01, loop, False)
    del cb
    gc.collect()
    yield from asyncio.sleep(0.1, loop=loop)


def test_ceil_call_later():
    cb = mock.Mock()
    loop = mock.Mock()
    loop.time.return_value = 10.1
    helpers.call_later(cb, 10.1, loop)
    loop.call_at.assert_called_with(21.0, cb)


def test_ceil_call_later_no_timeout():
    cb = mock.Mock()
    loop = mock.Mock()
    helpers.call_later(cb, 0, loop)
    assert not loop.call_at.called


@asyncio.coroutine
def test_ceil_timeout(loop):
    with helpers.CeilTimeout(None, loop=loop) as timeout:
        assert timeout._timeout is None
        assert timeout._cancel_handler is None


def test_ceil_timeout_no_task(loop):
    with pytest.raises(RuntimeError):
        with helpers.CeilTimeout(10, loop=loop):
            pass


# -------------------------------- ContentDisposition -------------------

def test_content_disposition():
    assert (helpers.content_disposition_header('attachment', foo='bar') ==
            'attachment; foo="bar"')


def test_content_disposition_bad_type():
    with pytest.raises(ValueError):
        helpers.content_disposition_header('foo bar')
    with pytest.raises(ValueError):
        helpers.content_disposition_header('—Ç–µ—Å—Ç')
    with pytest.raises(ValueError):
        helpers.content_disposition_header('foo\x00bar')
    with pytest.raises(ValueError):
        helpers.content_disposition_header('')


def test_set_content_disposition_bad_param():
    with pytest.raises(ValueError):
        helpers.content_disposition_header('inline', **{'foo bar': 'baz'})
    with pytest.raises(ValueError):
        helpers.content_disposition_header('inline', **{'—Ç–µ—Å—Ç': 'baz'})
    with pytest.raises(ValueError):
        helpers.content_disposition_header('inline', **{'': 'baz'})
    with pytest.raises(ValueError):
        helpers.content_disposition_header('inline',
                                           **{'foo\x00bar': 'baz'})


# --------------------- proxies_from_env ------------------------------

def test_proxies_from_env_http(mocker):
    url = URL('http://aiohttp.io/path')
    mocker.patch.dict(os.environ, {'http_proxy': str(url)})
    ret = helpers.proxies_from_env()
    assert ret.keys() == {'http'}
    assert ret['http'].proxy == url
    assert ret['http'].proxy_auth is None


def test_proxies_from_env_http_proxy_for_https_proto(mocker):
    url = URL('http://aiohttp.io/path')
    mocker.patch.dict(os.environ, {'https_proxy': str(url)})
    ret = helpers.proxies_from_env()
    assert ret.keys() == {'https'}
    assert ret['https'].proxy == url
    assert ret['https'].proxy_auth is None


def test_proxies_from_env_https_proxy_skipped(mocker):
    url = URL('https://aiohttp.io/path')
    mocker.patch.dict(os.environ, {'https_proxy': str(url)})
    log = mocker.patch('aiohttp.log.client_logger.warning')
    assert helpers.proxies_from_env() == {}
    log.assert_called_with('HTTPS proxies %s are not supported, ignoring',
                           URL('https://aiohttp.io/path'))


def test_proxies_from_env_http_with_auth(mocker):
    url = URL('http://user:pass@aiohttp.io/path')
    mocker.patch.dict(os.environ, {'http_proxy': str(url)})
    ret = helpers.proxies_from_env()
    assert ret.keys() == {'http'}
    assert ret['http'].proxy == url.with_user(None)
    proxy_auth = ret['http'].proxy_auth
    assert proxy_auth.login == 'user'
    assert proxy_auth.password == 'pass'
    assert proxy_auth.encoding == 'latin1'
