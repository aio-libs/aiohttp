import asyncio
import datetime
import gc
import os
import platform
import tempfile
from unittest import mock

import pytest
from multidict import MultiDict
from yarl import URL

from aiohttp import helpers
from aiohttp.abc import AbstractAccessLogger


IS_PYPY = platform.python_implementation() == 'PyPy'


# ------------------- parse_mimetype ----------------------------------

@pytest.mark.parametrize('mimetype, expected', [
    ('', helpers.MimeType('', '', '', MultiDict())),
    ('*', helpers.MimeType('*', '*', '', MultiDict())),
    ('application/json',
     helpers.MimeType('application', 'json', '', MultiDict())),
    ('application/json;  charset=utf-8',
     helpers.MimeType('application', 'json', '',
                      MultiDict({'charset': 'utf-8'}))),
    ('''application/json; charset=utf-8;''',
     helpers.MimeType('application', 'json', '',
                      MultiDict({'charset': 'utf-8'}))),
    ('ApPlIcAtIoN/JSON;ChaRseT="UTF-8"',
     helpers.MimeType('application', 'json', '',
                      MultiDict({'charset': 'UTF-8'}))),
    ('application/rss+xml',
     helpers.MimeType('application', 'rss', 'xml', MultiDict())),
    ('text/plain;base64',
     helpers.MimeType('text', 'plain', '', MultiDict({'base64': ''})))
])
def test_parse_mimetype(mimetype, expected):
    result = helpers.parse_mimetype(mimetype)

    assert isinstance(result, helpers.MimeType)
    assert result == expected


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


@pytest.mark.skip(
    IS_PYPY,
    """
    Because of patching :py:class:`datetime.datetime`, under PyPy it
    fails in :py:func:`isinstance` call in
    :py:meth:`datetime.datetime.__sub__` (called from
    :py:meth:`aiohttp.helpers.AccessLogger._format_t`):

    *** TypeError: isinstance() arg 2 must be a class, type, or tuple of classes and types

    (Pdb) from datetime import datetime
    (Pdb) isinstance(now, datetime)
    *** TypeError: isinstance() arg 2 must be a class, type, or tuple of classes and types
    (Pdb) datetime.__class__
    <class 'unittest.mock.MagicMock'>
    (Pdb) isinstance(now, datetime.__class__)
    False

    Ref: https://bitbucket.org/pypy/pypy/issues/1187/call-to-isinstance-in-__sub__-self-other
    Ref: https://github.com/celery/celery/issues/811
    Ref: https://stackoverflow.com/a/46102240/595220
    """,  # noqa: E501
)
def test_access_logger_atoms(mocker):
    utcnow = datetime.datetime(1843, 1, 1, 0, 30)
    mock_datetime = mocker.patch("aiohttp.helpers.datetime.datetime")
    mock_getpid = mocker.patch("os.getpid")
    mock_datetime.utcnow.return_value = utcnow
    mock_getpid.return_value = 42
    log_format = '%a %t %P %r %s %b %T %Tf %D "%{H1}i" "%{H2}i"'
    mock_logger = mock.Mock()
    access_logger = helpers.AccessLogger(mock_logger, log_format)
    request = mock.Mock(headers={'H1': 'a', 'H2': 'b'},
                        method="GET", path_qs="/path",
                        version=(1, 1),
                        remote="127.0.0.2")
    response = mock.Mock(headers={}, body_length=42, status=200)
    access_logger.log(request, response, 3.1415926)
    assert not mock_logger.exception.called
    expected = ('127.0.0.2 [01/Jan/1843:00:29:56 +0000] <42> '
                'GET /path HTTP/1.1 200 42 3 3.141593 3141593 "a" "b"')
    extra = {
        'first_request_line': 'GET /path HTTP/1.1',
        'process_id': '<42>',
        'remote_address': '127.0.0.2',
        'request_start_time': '[01/Jan/1843:00:29:56 +0000]',
        'request_time': 3,
        'request_time_frac': '3.141593',
        'request_time_micro': 3141593,
        'response_size': 42,
        'response_status': 200,
        'request_header': {'H1': 'a', 'H2': 'b'},
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
        'request_header': {"User-Agent": "Mock/1.0", 'None': '-'},
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


class ReifyMixin:

    reify = NotImplemented

    def test_reify(self):
        class A:
            def __init__(self):
                self._cache = {}

            @self.reify
            def prop(self):
                return 1

        a = A()
        assert 1 == a.prop

    def test_reify_class(self):
        class A:
            def __init__(self):
                self._cache = {}

            @self.reify
            def prop(self):
                """Docstring."""
                return 1

        assert isinstance(A.prop, self.reify)
        assert 'Docstring.' == A.prop.__doc__

    def test_reify_assignment(self):
        class A:
            def __init__(self):
                self._cache = {}

            @self.reify
            def prop(self):
                return 1

        a = A()

        with pytest.raises(AttributeError):
            a.prop = 123


class TestPyReify(ReifyMixin):
    reify = helpers.reify_py


if not helpers.NO_EXTENSIONS and not IS_PYPY:
    class TestCReify(ReifyMixin):
        reify = helpers.reify_c

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

        if helpers.PY_37:
            assert m_asyncio.current_task.return_value.cancel.called
        else:
            assert m_asyncio.Task.current_task.return_value.cancel.called


def test_timer_context_no_task(loop):
    with pytest.raises(RuntimeError):
        with helpers.TimerContext(loop):
            pass


# -------------------------------- CeilTimeout --------------------------


async def test_weakref_handle(loop):
    cb = mock.Mock()
    helpers.weakref_handle(cb, 'test', 0.01, loop, False)
    await asyncio.sleep(0.1, loop=loop)
    assert cb.test.called


async def test_weakref_handle_weak(loop):
    cb = mock.Mock()
    helpers.weakref_handle(cb, 'test', 0.01, loop, False)
    del cb
    gc.collect()
    await asyncio.sleep(0.1, loop=loop)


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


async def test_ceil_timeout(loop):
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


# ------------- set_result / set_exception ----------------------


async def test_set_result(loop):
    fut = loop.create_future()
    helpers.set_result(fut, 123)
    assert 123 == await fut


async def test_set_result_cancelled(loop):
    fut = loop.create_future()
    fut.cancel()
    helpers.set_result(fut, 123)

    with pytest.raises(asyncio.CancelledError):
        await fut


async def test_set_exception(loop):
    fut = loop.create_future()
    helpers.set_exception(fut, RuntimeError())
    with pytest.raises(RuntimeError):
        await fut


async def test_set_exception_cancelled(loop):
    fut = loop.create_future()
    fut.cancel()
    helpers.set_exception(fut, RuntimeError())

    with pytest.raises(asyncio.CancelledError):
        await fut


# ----------- ChainMapProxy --------------------------

class TestChainMapProxy:
    @pytest.mark.skipif(not helpers.PY_36,
                        reason="Requires Python 3.6+")
    def test_inheritance(self):
        with pytest.raises(TypeError):
            class A(helpers.ChainMapProxy):
                pass

    def test_getitem(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp['a'] == 2
        assert cp['b'] == 3

    def test_getitem_not_found(self):
        d = {'a': 1}
        cp = helpers.ChainMapProxy([d])
        with pytest.raises(KeyError):
            cp['b']

    def test_get(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get('a') == 2

    def test_get_default(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get('c', 4) == 4

    def test_get_non_default(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get('a', 4) == 2

    def test_len(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert len(cp) == 2

    def test_iter(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert set(cp) == {'a', 'b'}

    def test_contains(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert 'a' in cp
        assert 'b' in cp
        assert 'c' not in cp

    def test_bool(self):
        assert helpers.ChainMapProxy([{'a': 1}])
        assert not helpers.ChainMapProxy([{}, {}])
        assert not helpers.ChainMapProxy([])

    def test_repr(self):
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        expected = "ChainMapProxy({!r}, {!r})".format(d1, d2)
        assert expected == repr(cp)
