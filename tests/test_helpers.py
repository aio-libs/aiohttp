import asyncio
import base64
import gc
import os
import platform
from math import modf
from unittest import mock

import pytest
from multidict import MultiDict
from yarl import URL

from aiohttp import helpers
from aiohttp.helpers import is_expected_content_type

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
def test_parse_mimetype(mimetype, expected) -> None:
    result = helpers.parse_mimetype(mimetype)

    assert isinstance(result, helpers.MimeType)
    assert result == expected


# ------------------- guess_filename ----------------------------------

def test_guess_filename_with_file_object(tmp_path) -> None:
    file_path = tmp_path / 'test_guess_filename'
    with file_path.open('w+b') as fp:
        assert (helpers.guess_filename(fp, 'no-throw') is not None)


def test_guess_filename_with_path(tmp_path) -> None:
    file_path = tmp_path / 'test_guess_filename'
    assert (helpers.guess_filename(file_path, 'no-throw') is not None)


def test_guess_filename_with_default() -> None:
    assert (helpers.guess_filename(None, 'no-throw') == 'no-throw')


# ------------------- BasicAuth -----------------------------------

def test_basic_auth1() -> None:
    # missing password here
    with pytest.raises(ValueError):
        helpers.BasicAuth(None)


def test_basic_auth2() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth('nkim', None)


def test_basic_with_auth_colon_in_login() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth('nkim:1', 'pwd')


def test_basic_auth3() -> None:
    auth = helpers.BasicAuth('nkim')
    assert auth.login == 'nkim'
    assert auth.password == ''


def test_basic_auth4() -> None:
    auth = helpers.BasicAuth('nkim', 'pwd')
    assert auth.login == 'nkim'
    assert auth.password == 'pwd'
    assert auth.encode() == 'Basic bmtpbTpwd2Q='


@pytest.mark.parametrize('header', (
    'Basic bmtpbTpwd2Q=',
    'basic bmtpbTpwd2Q=',
))
def test_basic_auth_decode(header) -> None:
    auth = helpers.BasicAuth.decode(header)
    assert auth.login == 'nkim'
    assert auth.password == 'pwd'


def test_basic_auth_invalid() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode('bmtpbTpwd2Q=')


def test_basic_auth_decode_not_basic() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode('Complex bmtpbTpwd2Q=')


def test_basic_auth_decode_bad_base64() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode('Basic bmtpbTpwd2Q')


@pytest.mark.parametrize('header', ('Basic ???', 'Basic   '))
def test_basic_auth_decode_illegal_chars_base64(header) -> None:
    with pytest.raises(ValueError, match='Invalid base64 encoding.'):
        helpers.BasicAuth.decode(header)


def test_basic_auth_decode_invalid_credentials() -> None:
    with pytest.raises(ValueError, match='Invalid credentials.'):
        header = 'Basic {}'.format(base64.b64encode(b'username').decode())
        helpers.BasicAuth.decode(header)


@pytest.mark.parametrize('credentials, expected_auth', (
    (':', helpers.BasicAuth(
        login='', password='', encoding='latin1')),
    ('username:', helpers.BasicAuth(
        login='username', password='', encoding='latin1')),
    (':password', helpers.BasicAuth(
        login='', password='password', encoding='latin1')),
    ('username:password', helpers.BasicAuth(
        login='username', password='password', encoding='latin1')),
))
def test_basic_auth_decode_blank_username(credentials, expected_auth) -> None:
    header = 'Basic {}'.format(base64.b64encode(credentials.encode()).decode())
    assert helpers.BasicAuth.decode(header) == expected_auth


def test_basic_auth_from_url() -> None:
    url = URL('http://user:pass@example.com')
    auth = helpers.BasicAuth.from_url(url)
    assert auth.login == 'user'
    assert auth.password == 'pass'


def test_basic_auth_from_not_url() -> None:
    with pytest.raises(TypeError):
        helpers.BasicAuth.from_url('http://user:pass@example.com')


class ReifyMixin:

    reify = NotImplemented

    def test_reify(self) -> None:
        class A:
            def __init__(self):
                self._cache = {}

            @self.reify
            def prop(self):
                return 1

        a = A()
        assert 1 == a.prop

    def test_reify_class(self) -> None:
        class A:
            def __init__(self):
                self._cache = {}

            @self.reify
            def prop(self):
                """Docstring."""
                return 1

        assert isinstance(A.prop, self.reify)
        assert 'Docstring.' == A.prop.__doc__

    def test_reify_assignment(self) -> None:
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


if not helpers.NO_EXTENSIONS and not IS_PYPY and hasattr(helpers, 'reify_c'):
    class TestCReify(ReifyMixin):
        reify = helpers.reify_c

# ----------------------------------- is_ip_address() ----------------------


def test_is_ip_address() -> None:
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


def test_is_ip_address_bytes() -> None:
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


def test_ipv4_addresses() -> None:
    ip_addresses = [
        '0.0.0.0',
        '127.0.0.1',
        '255.255.255.255',
    ]
    for address in ip_addresses:
        assert helpers.is_ipv4_address(address)
        assert not helpers.is_ipv6_address(address)
        assert helpers.is_ip_address(address)


def test_ipv6_addresses() -> None:
    ip_addresses = [
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
        assert not helpers.is_ipv4_address(address)
        assert helpers.is_ipv6_address(address)
        assert helpers.is_ip_address(address)


def test_host_addresses() -> None:
    hosts = [
        'www.four.part.host'
        'www.python.org',
        'foo.bar',
        'localhost',
    ]
    for host in hosts:
        assert not helpers.is_ip_address(host)


def test_is_ip_address_invalid_type() -> None:
    with pytest.raises(TypeError):
        helpers.is_ip_address(123)

    with pytest.raises(TypeError):
        helpers.is_ip_address(object())


# ----------------------------------- TimeoutHandle -------------------

def test_timeout_handle(loop) -> None:
    handle = helpers.TimeoutHandle(loop, 10.2)
    cb = mock.Mock()
    handle.register(cb)
    assert cb == handle._callbacks[0][0]
    handle.close()
    assert not handle._callbacks


def test_timeout_handle_cb_exc(loop) -> None:
    handle = helpers.TimeoutHandle(loop, 10.2)
    cb = mock.Mock()
    handle.register(cb)
    cb.side_effect = ValueError()
    handle()
    assert cb.called
    assert not handle._callbacks


def test_timer_context_cancelled() -> None:
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


def test_timer_context_no_task(loop) -> None:
    with pytest.raises(RuntimeError):
        with helpers.TimerContext(loop):
            pass


async def test_weakref_handle(loop) -> None:
    cb = mock.Mock()
    helpers.weakref_handle(cb, 'test', 0.01, loop, False)
    await asyncio.sleep(0.1)
    assert cb.test.called


async def test_weakref_handle_weak(loop) -> None:
    cb = mock.Mock()
    helpers.weakref_handle(cb, 'test', 0.01, loop, False)
    del cb
    gc.collect()
    await asyncio.sleep(0.1)

# -------------------- ceil math -------------------------


def test_ceil_call_later() -> None:
    cb = mock.Mock()
    loop = mock.Mock()
    loop.time.return_value = 10.1
    helpers.call_later(cb, 10.1, loop)
    loop.call_at.assert_called_with(21.0, cb)


def test_ceil_call_later_no_timeout() -> None:
    cb = mock.Mock()
    loop = mock.Mock()
    helpers.call_later(cb, 0, loop)
    assert not loop.call_at.called


async def test_ceil_timeout_none(loop) -> None:
    async with helpers.ceil_timeout(None) as cm:
        assert cm.deadline is None


async def test_ceil_timeout_round(loop) -> None:
    async with helpers.ceil_timeout(1.5) as cm:
        frac, integer = modf(cm.deadline)
        assert frac == 0


# -------------------------------- ContentDisposition -------------------

def test_content_disposition() -> None:
    assert (helpers.content_disposition_header('attachment', foo='bar') ==
            'attachment; foo="bar"')


def test_content_disposition_bad_type() -> None:
    with pytest.raises(ValueError):
        helpers.content_disposition_header('foo bar')
    with pytest.raises(ValueError):
        helpers.content_disposition_header('—Ç–µ—Å—Ç')
    with pytest.raises(ValueError):
        helpers.content_disposition_header('foo\x00bar')
    with pytest.raises(ValueError):
        helpers.content_disposition_header('')


def test_set_content_disposition_bad_param() -> None:
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

@pytest.mark.parametrize('protocol', ['http', 'https', 'ws', 'wss'])
def test_proxies_from_env(monkeypatch, protocol) -> None:
    url = URL('http://aiohttp.io/path')
    monkeypatch.setenv(protocol + '_proxy', str(url))
    ret = helpers.proxies_from_env()
    assert ret.keys() == {protocol}
    assert ret[protocol].proxy == url
    assert ret[protocol].proxy_auth is None


@pytest.mark.parametrize('protocol', ['https', 'wss'])
def test_proxies_from_env_skipped(monkeypatch, caplog, protocol) -> None:
    url = URL(protocol + '://aiohttp.io/path')
    monkeypatch.setenv(protocol + '_proxy', str(url))
    assert helpers.proxies_from_env() == {}
    assert len(caplog.records) == 1
    log_message = (
        '{proto!s} proxies {url!s} are not supported, ignoring'.
        format(proto=protocol.upper(), url=url)
    )
    assert caplog.record_tuples == [('aiohttp.client', 30, log_message)]


def test_proxies_from_env_http_with_auth(mocker) -> None:
    url = URL('http://user:pass@aiohttp.io/path')
    mocker.patch.dict(os.environ, {'http_proxy': str(url)})
    ret = helpers.proxies_from_env()
    assert ret.keys() == {'http'}
    assert ret['http'].proxy == url.with_user(None)
    proxy_auth = ret['http'].proxy_auth
    assert proxy_auth.login == 'user'
    assert proxy_auth.password == 'pass'
    assert proxy_auth.encoding == 'latin1'

# ------------ get_running_loop ---------------------------------


def test_get_running_loop_not_running(loop) -> None:
    with pytest.raises(
            RuntimeError,
            match="The object should be created within an async function"):
        helpers.get_running_loop()


async def test_get_running_loop_ok(loop) -> None:
    assert helpers.get_running_loop() is loop


# ------------- set_result / set_exception ----------------------


async def test_set_result(loop) -> None:
    fut = loop.create_future()
    helpers.set_result(fut, 123)
    assert 123 == await fut


async def test_set_result_cancelled(loop) -> None:
    fut = loop.create_future()
    fut.cancel()
    helpers.set_result(fut, 123)

    with pytest.raises(asyncio.CancelledError):
        await fut


async def test_set_exception(loop) -> None:
    fut = loop.create_future()
    helpers.set_exception(fut, RuntimeError())
    with pytest.raises(RuntimeError):
        await fut


async def test_set_exception_cancelled(loop) -> None:
    fut = loop.create_future()
    fut.cancel()
    helpers.set_exception(fut, RuntimeError())

    with pytest.raises(asyncio.CancelledError):
        await fut


# ----------- ChainMapProxy --------------------------

class TestChainMapProxy:
    @pytest.mark.skipif(not helpers.PY_36,
                        reason="Requires Python 3.6+")
    def test_inheritance(self) -> None:
        with pytest.raises(TypeError):
            class A(helpers.ChainMapProxy):
                pass

    def test_getitem(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp['a'] == 2
        assert cp['b'] == 3

    def test_getitem_not_found(self) -> None:
        d = {'a': 1}
        cp = helpers.ChainMapProxy([d])
        with pytest.raises(KeyError):
            cp['b']

    def test_get(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get('a') == 2

    def test_get_default(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get('c', 4) == 4

    def test_get_non_default(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get('a', 4) == 2

    def test_len(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert len(cp) == 2

    def test_iter(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert set(cp) == {'a', 'b'}

    def test_contains(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert 'a' in cp
        assert 'b' in cp
        assert 'c' not in cp

    def test_bool(self) -> None:
        assert helpers.ChainMapProxy([{'a': 1}])
        assert not helpers.ChainMapProxy([{}, {}])
        assert not helpers.ChainMapProxy([])

    def test_repr(self) -> None:
        d1 = {'a': 2, 'b': 3}
        d2 = {'a': 1}
        cp = helpers.ChainMapProxy([d1, d2])
        expected = "ChainMapProxy({!r}, {!r})".format(d1, d2)
        assert expected == repr(cp)


def test_is_expected_content_type_json_match_exact():
    expected_ct = 'application/json'
    response_ct = 'application/json'
    assert is_expected_content_type(response_content_type=response_ct,
                                    expected_content_type=expected_ct)


def test_is_expected_content_type_json_match_partially():
    expected_ct = 'application/json'
    response_ct = 'application/alto-costmap+json'  # mime-type from rfc7285
    assert is_expected_content_type(response_content_type=response_ct,
                                    expected_content_type=expected_ct)


def test_is_expected_content_type_non_json_match_exact():
    expected_ct = 'text/javascript'
    response_ct = 'text/javascript'
    assert is_expected_content_type(response_content_type=response_ct,
                                    expected_content_type=expected_ct)


def test_is_expected_content_type_non_json_not_match():
    expected_ct = 'application/json'
    response_ct = 'text/plain'
    assert not is_expected_content_type(response_content_type=response_ct,
                                        expected_content_type=expected_ct)
