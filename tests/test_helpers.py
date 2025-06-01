import asyncio
import base64
import datetime
import gc
import sys
import weakref
from http.cookies import CookieError, Morsel, SimpleCookie
from math import ceil, modf
from pathlib import Path
from typing import Dict, Iterator, Optional, Union
from unittest import mock
from urllib.request import getproxies_environment

import pytest
from multidict import CIMultiDict, MultiDict, MultiDictProxy
from yarl import URL

from aiohttp import helpers, web
from aiohttp.helpers import (
    EMPTY_BODY_METHODS,
    is_expected_content_type,
    must_be_empty_body,
    parse_cookie_headers,
    parse_http_date,
    preserve_morsel_with_coded_value,
    should_remove_content_length,
)

# ------------------- parse_mimetype ----------------------------------


@pytest.mark.parametrize(
    "mimetype, expected",
    [
        ("", helpers.MimeType("", "", "", MultiDictProxy(MultiDict()))),
        ("*", helpers.MimeType("*", "*", "", MultiDictProxy(MultiDict()))),
        (
            "application/json",
            helpers.MimeType("application", "json", "", MultiDictProxy(MultiDict())),
        ),
        (
            "application/json;  charset=utf-8",
            helpers.MimeType(
                "application",
                "json",
                "",
                MultiDictProxy(MultiDict({"charset": "utf-8"})),
            ),
        ),
        (
            """application/json; charset=utf-8;""",
            helpers.MimeType(
                "application",
                "json",
                "",
                MultiDictProxy(MultiDict({"charset": "utf-8"})),
            ),
        ),
        (
            'ApPlIcAtIoN/JSON;ChaRseT="UTF-8"',
            helpers.MimeType(
                "application",
                "json",
                "",
                MultiDictProxy(MultiDict({"charset": "UTF-8"})),
            ),
        ),
        (
            "application/rss+xml",
            helpers.MimeType("application", "rss", "xml", MultiDictProxy(MultiDict())),
        ),
        (
            "text/plain;base64",
            helpers.MimeType(
                "text", "plain", "", MultiDictProxy(MultiDict({"base64": ""}))
            ),
        ),
    ],
)
def test_parse_mimetype(mimetype: str, expected: helpers.MimeType) -> None:
    result = helpers.parse_mimetype(mimetype)

    assert isinstance(result, helpers.MimeType)
    assert result == expected


# ------------------- guess_filename ----------------------------------


def test_guess_filename_with_file_object(tmp_path: Path) -> None:
    file_path = tmp_path / "test_guess_filename"
    with file_path.open("w+b") as fp:
        assert helpers.guess_filename(fp, "no-throw") is not None


def test_guess_filename_with_path(tmp_path: Path) -> None:
    file_path = tmp_path / "test_guess_filename"
    assert helpers.guess_filename(file_path, "no-throw") is not None


def test_guess_filename_with_default() -> None:
    assert helpers.guess_filename(None, "no-throw") == "no-throw"


# ------------------- BasicAuth -----------------------------------


def test_basic_auth1() -> None:
    # missing password here
    with pytest.raises(ValueError):
        helpers.BasicAuth(None)  # type: ignore[arg-type]


def test_basic_auth2() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth("nkim", None)  # type: ignore[arg-type]


def test_basic_with_auth_colon_in_login() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth("nkim:1", "pwd")


def test_basic_auth3() -> None:
    auth = helpers.BasicAuth("nkim")
    assert auth.login == "nkim"
    assert auth.password == ""


def test_basic_auth4() -> None:
    auth = helpers.BasicAuth("nkim", "pwd")
    assert auth.login == "nkim"
    assert auth.password == "pwd"
    assert auth.encode() == "Basic bmtpbTpwd2Q="


@pytest.mark.parametrize(
    "header",
    (
        "Basic bmtpbTpwd2Q=",
        "basic bmtpbTpwd2Q=",
    ),
)
def test_basic_auth_decode(header: str) -> None:
    auth = helpers.BasicAuth.decode(header)
    assert auth.login == "nkim"
    assert auth.password == "pwd"


def test_basic_auth_invalid() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode("bmtpbTpwd2Q=")


def test_basic_auth_decode_not_basic() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode("Complex bmtpbTpwd2Q=")


def test_basic_auth_decode_bad_base64() -> None:
    with pytest.raises(ValueError):
        helpers.BasicAuth.decode("Basic bmtpbTpwd2Q")


@pytest.mark.parametrize("header", ("Basic ???", "Basic   "))
def test_basic_auth_decode_illegal_chars_base64(header: str) -> None:
    with pytest.raises(ValueError, match="Invalid base64 encoding."):
        helpers.BasicAuth.decode(header)


def test_basic_auth_decode_invalid_credentials() -> None:
    with pytest.raises(ValueError, match="Invalid credentials."):
        header = "Basic {}".format(base64.b64encode(b"username").decode())
        helpers.BasicAuth.decode(header)


@pytest.mark.parametrize(
    "credentials, expected_auth",
    (
        (":", helpers.BasicAuth(login="", password="", encoding="latin1")),
        (
            "username:",
            helpers.BasicAuth(login="username", password="", encoding="latin1"),
        ),
        (
            ":password",
            helpers.BasicAuth(login="", password="password", encoding="latin1"),
        ),
        (
            "username:password",
            helpers.BasicAuth(login="username", password="password", encoding="latin1"),
        ),
    ),
)
def test_basic_auth_decode_blank_username(  # type: ignore[misc]
    credentials: str, expected_auth: helpers.BasicAuth
) -> None:
    header = f"Basic {base64.b64encode(credentials.encode()).decode()}"
    assert helpers.BasicAuth.decode(header) == expected_auth


def test_basic_auth_from_url() -> None:
    url = URL("http://user:pass@example.com")
    auth = helpers.BasicAuth.from_url(url)
    assert auth is not None
    assert auth.login == "user"
    assert auth.password == "pass"


def test_basic_auth_no_user_from_url() -> None:
    url = URL("http://:pass@example.com")
    auth = helpers.BasicAuth.from_url(url)
    assert auth is not None
    assert auth.login == ""
    assert auth.password == "pass"


def test_basic_auth_no_auth_from_url() -> None:
    url = URL("http://example.com")
    auth = helpers.BasicAuth.from_url(url)
    assert auth is None


def test_basic_auth_from_not_url() -> None:
    with pytest.raises(TypeError):
        helpers.BasicAuth.from_url("http://user:pass@example.com")  # type: ignore[arg-type]


# ----------------------------------- is_ip_address() ----------------------


def test_is_ip_address() -> None:
    assert helpers.is_ip_address("127.0.0.1")
    assert helpers.is_ip_address("::1")
    assert helpers.is_ip_address("FE80:0000:0000:0000:0202:B3FF:FE1E:8329")

    # Hostnames
    assert not helpers.is_ip_address("localhost")
    assert not helpers.is_ip_address("www.example.com")


def test_ipv4_addresses() -> None:
    ip_addresses = [
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
    ]
    for address in ip_addresses:
        assert helpers.is_ip_address(address)


def test_ipv6_addresses() -> None:
    ip_addresses = [
        "0:0:0:0:0:0:0:0",
        "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
        "00AB:0002:3008:8CFD:00AB:0002:3008:8CFD",
        "00ab:0002:3008:8cfd:00ab:0002:3008:8cfd",
        "AB:02:3008:8CFD:AB:02:3008:8CFD",
        "AB:02:3008:8CFD::02:3008:8CFD",
        "::",
        "1::1",
    ]
    for address in ip_addresses:
        assert helpers.is_ip_address(address)


def test_host_addresses() -> None:
    hosts = [
        "www.four.part.host",
        "www.python.org",
        "foo.bar",
        "localhost",
    ]
    for host in hosts:
        assert not helpers.is_ip_address(host)


def test_is_ip_address_invalid_type() -> None:
    with pytest.raises(TypeError):
        helpers.is_ip_address(123)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        helpers.is_ip_address(object())  # type: ignore[arg-type]


# ----------------------------------- TimeoutHandle -------------------


def test_timeout_handle(loop: asyncio.AbstractEventLoop) -> None:
    handle = helpers.TimeoutHandle(loop, 10.2)
    cb = mock.Mock()
    handle.register(cb)
    assert cb == handle._callbacks[0][0]
    handle.close()
    assert not handle._callbacks


def test_when_timeout_smaller_second(loop: asyncio.AbstractEventLoop) -> None:
    timeout = 0.1
    timer = loop.time() + timeout

    handle = helpers.TimeoutHandle(loop, timeout)
    assert handle is not None
    start_handle = handle.start()
    assert start_handle is not None
    when = start_handle.when()
    handle.close()

    assert isinstance(when, float)
    assert when - timer == pytest.approx(0, abs=0.001)


def test_when_timeout_smaller_second_with_low_threshold(
    loop: asyncio.AbstractEventLoop,
) -> None:
    timeout = 0.1
    timer = loop.time() + timeout

    handle = helpers.TimeoutHandle(loop, timeout, 0.01)
    assert handle is not None
    start_handle = handle.start()
    assert start_handle is not None
    when = start_handle.when()
    handle.close()

    assert isinstance(when, int)
    assert when == ceil(timer)


def test_timeout_handle_cb_exc(loop: asyncio.AbstractEventLoop) -> None:
    handle = helpers.TimeoutHandle(loop, 10.2)
    cb = mock.Mock()
    handle.register(cb)
    cb.side_effect = ValueError()
    handle()
    assert cb.called
    assert not handle._callbacks


def test_timer_context_not_cancelled() -> None:
    with mock.patch("aiohttp.helpers.asyncio") as m_asyncio:
        m_asyncio.TimeoutError = asyncio.TimeoutError
        loop = mock.Mock()
        ctx = helpers.TimerContext(loop)
        ctx.timeout()

        with pytest.raises(asyncio.TimeoutError):
            with ctx:
                pass

        assert not m_asyncio.current_task.return_value.cancel.called


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Python 3.11+ is required for .cancelling()"
)
async def test_timer_context_timeout_does_not_leak_upward() -> None:
    """Verify that the TimerContext does not leak cancellation outside the context manager."""
    loop = asyncio.get_running_loop()
    ctx = helpers.TimerContext(loop)
    current_task = asyncio.current_task()
    assert current_task is not None
    with pytest.raises(asyncio.TimeoutError):
        with ctx:
            assert current_task.cancelling() == 0
            loop.call_soon(ctx.timeout)
            await asyncio.sleep(1)

    # After the context manager exits, the task should no longer be cancelling
    assert current_task.cancelling() == 0


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Python 3.11+ is required for .cancelling()"
)
async def test_timer_context_timeout_does_swallow_cancellation() -> None:
    """Verify that the TimerContext does not swallow cancellation."""
    loop = asyncio.get_running_loop()
    current_task = asyncio.current_task()
    assert current_task is not None
    ctx = helpers.TimerContext(loop)

    async def task_with_timeout() -> None:
        new_task = asyncio.current_task()
        assert new_task is not None
        with pytest.raises(asyncio.TimeoutError):
            with ctx:
                assert new_task.cancelling() == 0
                await asyncio.sleep(1)

    task = asyncio.create_task(task_with_timeout())
    await asyncio.sleep(0)
    task.cancel()
    assert task.cancelling() == 1
    ctx.timeout()

    # Cancellation should not leak into the current task
    assert current_task.cancelling() == 0
    # Cancellation should not be swallowed if the task is cancelled
    # and it also times out
    await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        await task
    assert task.cancelling() == 1


def test_timer_context_no_task(loop: asyncio.AbstractEventLoop) -> None:
    with pytest.raises(RuntimeError):
        with helpers.TimerContext(loop):
            pass


async def test_weakref_handle(loop: asyncio.AbstractEventLoop) -> None:
    cb = mock.Mock()
    helpers.weakref_handle(cb, "test", 0.01, loop)
    await asyncio.sleep(0.1)
    assert cb.test.called


async def test_weakref_handle_with_small_threshold(
    loop: asyncio.AbstractEventLoop,
) -> None:
    cb = mock.Mock()
    loop = mock.Mock()
    loop.time.return_value = 10
    helpers.weakref_handle(cb, "test", 0.1, loop, 0.01)
    loop.call_at.assert_called_with(
        11, helpers._weakref_handle, (weakref.ref(cb), "test")
    )


async def test_weakref_handle_weak(loop: asyncio.AbstractEventLoop) -> None:
    cb = mock.Mock()
    helpers.weakref_handle(cb, "test", 0.01, loop)
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


async def test_ceil_timeout_round(loop: asyncio.AbstractEventLoop) -> None:
    async with helpers.ceil_timeout(7.5) as cm:
        if sys.version_info >= (3, 11):
            w = cm.when()
            assert w is not None
            frac, integer = modf(w)
        else:
            assert cm.deadline is not None
            frac, integer = modf(cm.deadline)
        assert frac == 0


async def test_ceil_timeout_small(loop: asyncio.AbstractEventLoop) -> None:
    async with helpers.ceil_timeout(1.1) as cm:
        if sys.version_info >= (3, 11):
            w = cm.when()
            assert w is not None
            frac, integer = modf(w)
        else:
            assert cm.deadline is not None
            frac, integer = modf(cm.deadline)
        # a chance for exact integer with zero fraction is negligible
        assert frac != 0


def test_ceil_call_later_with_small_threshold() -> None:
    cb = mock.Mock()
    loop = mock.Mock()
    loop.time.return_value = 10.1
    helpers.call_later(cb, 4.5, loop, 1)
    loop.call_at.assert_called_with(15, cb)


def test_ceil_call_later_no_timeout() -> None:
    cb = mock.Mock()
    loop = mock.Mock()
    helpers.call_later(cb, 0, loop)
    assert not loop.call_at.called


async def test_ceil_timeout_none(loop: asyncio.AbstractEventLoop) -> None:
    async with helpers.ceil_timeout(None) as cm:
        if sys.version_info >= (3, 11):
            assert cm.when() is None
        else:
            assert cm.deadline is None


async def test_ceil_timeout_small_with_overriden_threshold(
    loop: asyncio.AbstractEventLoop,
) -> None:
    async with helpers.ceil_timeout(1.5, ceil_threshold=1) as cm:
        if sys.version_info >= (3, 11):
            w = cm.when()
            assert w is not None
            frac, integer = modf(w)
        else:
            assert cm.deadline is not None
            frac, integer = modf(cm.deadline)
        assert frac == 0


# -------------------------------- ContentDisposition -------------------


@pytest.mark.parametrize(
    "params, quote_fields, _charset, expected",
    [
        (dict(foo="bar"), True, "utf-8", 'attachment; foo="bar"'),
        (dict(foo="bar[]"), True, "utf-8", 'attachment; foo="bar[]"'),
        (dict(foo=' a""b\\'), True, "utf-8", 'attachment; foo="\\ a\\"\\"b\\\\"'),
        (dict(foo="bär"), True, "utf-8", "attachment; foo*=utf-8''b%C3%A4r"),
        (dict(foo='bär "\\'), False, "utf-8", 'attachment; foo="bär \\"\\\\"'),
        (dict(foo="bär"), True, "latin-1", "attachment; foo*=latin-1''b%E4r"),
        (dict(filename="bär"), True, "utf-8", 'attachment; filename="b%C3%A4r"'),
        (dict(filename="bär"), True, "latin-1", 'attachment; filename="b%E4r"'),
        (
            dict(filename='bär "\\'),
            False,
            "utf-8",
            'attachment; filename="bär \\"\\\\"',
        ),
    ],
)
def test_content_disposition(
    params: Dict[str, str], quote_fields: bool, _charset: str, expected: str
) -> None:
    result = helpers.content_disposition_header(
        "attachment", quote_fields=quote_fields, _charset=_charset, params=params
    )
    assert result == expected


def test_content_disposition_bad_type() -> None:
    with pytest.raises(ValueError):
        helpers.content_disposition_header("foo bar")
    with pytest.raises(ValueError):
        helpers.content_disposition_header("—Ç–µ—Å—Ç")
    with pytest.raises(ValueError):
        helpers.content_disposition_header("foo\x00bar")
    with pytest.raises(ValueError):
        helpers.content_disposition_header("")


def test_set_content_disposition_bad_param() -> None:
    with pytest.raises(ValueError):
        helpers.content_disposition_header("inline", params={"foo bar": "baz"})
    with pytest.raises(ValueError):
        helpers.content_disposition_header("inline", params={"—Ç–µ—Å—Ç": "baz"})
    with pytest.raises(ValueError):
        helpers.content_disposition_header("inline", params={"": "baz"})
    with pytest.raises(ValueError):
        helpers.content_disposition_header("inline", params={"foo\x00bar": "baz"})


# --------------------- proxies_from_env ------------------------------


@pytest.mark.parametrize(
    ("proxy_env_vars", "url_input", "expected_scheme"),
    (
        ({"http_proxy": "http://aiohttp.io/path"}, "http://aiohttp.io/path", "http"),
        ({"https_proxy": "http://aiohttp.io/path"}, "http://aiohttp.io/path", "https"),
        ({"ws_proxy": "http://aiohttp.io/path"}, "http://aiohttp.io/path", "ws"),
        ({"wss_proxy": "http://aiohttp.io/path"}, "http://aiohttp.io/path", "wss"),
    ),
    indirect=["proxy_env_vars"],
    ids=("http", "https", "ws", "wss"),
)
@pytest.mark.usefixtures("proxy_env_vars")
def test_proxies_from_env(url_input: str, expected_scheme: str) -> None:
    url = URL(url_input)
    ret = helpers.proxies_from_env()
    assert ret.keys() == {expected_scheme}
    assert ret[expected_scheme].proxy == url
    assert ret[expected_scheme].proxy_auth is None


@pytest.mark.parametrize(
    ("proxy_env_vars", "url_input", "expected_scheme"),
    (
        (
            {"https_proxy": "https://aiohttp.io/path"},
            "https://aiohttp.io/path",
            "https",
        ),
        ({"wss_proxy": "wss://aiohttp.io/path"}, "wss://aiohttp.io/path", "wss"),
    ),
    indirect=["proxy_env_vars"],
    ids=("https", "wss"),
)
@pytest.mark.usefixtures("proxy_env_vars")
def test_proxies_from_env_skipped(
    caplog: pytest.LogCaptureFixture, url_input: str, expected_scheme: str
) -> None:
    url = URL(url_input)
    assert helpers.proxies_from_env() == {}
    assert len(caplog.records) == 1
    log_message = "{proto!s} proxies {url!s} are not supported, ignoring".format(
        proto=expected_scheme.upper(), url=url
    )
    assert caplog.record_tuples == [("aiohttp.client", 30, log_message)]


@pytest.mark.parametrize(
    ("proxy_env_vars", "url_input", "expected_scheme"),
    (
        (
            {"http_proxy": "http://user:pass@aiohttp.io/path"},
            "http://user:pass@aiohttp.io/path",
            "http",
        ),
    ),
    indirect=["proxy_env_vars"],
    ids=("http",),
)
@pytest.mark.usefixtures("proxy_env_vars")
def test_proxies_from_env_http_with_auth(url_input: str, expected_scheme: str) -> None:
    url = URL("http://user:pass@aiohttp.io/path")
    ret = helpers.proxies_from_env()
    assert ret.keys() == {expected_scheme}
    assert ret[expected_scheme].proxy == url.with_user(None)
    proxy_auth = ret[expected_scheme].proxy_auth
    assert proxy_auth is not None
    assert proxy_auth.login == "user"
    assert proxy_auth.password == "pass"
    assert proxy_auth.encoding == "latin1"


# --------------------- get_env_proxy_for_url ------------------------------


@pytest.fixture
def proxy_env_vars(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> object:
    for schema in getproxies_environment().keys():
        monkeypatch.delenv(f"{schema}_proxy", False)

    for proxy_type, proxy_list in request.param.items():
        monkeypatch.setenv(proxy_type, proxy_list)

    return request.param


@pytest.mark.parametrize(
    ("proxy_env_vars", "url_input", "expected_err_msg"),
    (
        (
            {"no_proxy": "aiohttp.io"},
            "http://aiohttp.io/path",
            r"Proxying is disallowed for `'aiohttp.io'`",
        ),
        (
            {"no_proxy": "aiohttp.io,proxy.com"},
            "http://aiohttp.io/path",
            r"Proxying is disallowed for `'aiohttp.io'`",
        ),
        (
            {"http_proxy": "http://example.com"},
            "https://aiohttp.io/path",
            r"No proxies found for `https://aiohttp.io/path` in the env",
        ),
        (
            {"https_proxy": "https://example.com"},
            "http://aiohttp.io/path",
            r"No proxies found for `http://aiohttp.io/path` in the env",
        ),
        (
            {},
            "https://aiohttp.io/path",
            r"No proxies found for `https://aiohttp.io/path` in the env",
        ),
        (
            {"https_proxy": "https://example.com"},
            "",
            r"No proxies found for `` in the env",
        ),
    ),
    indirect=["proxy_env_vars"],
    ids=(
        "url_matches_the_no_proxy_list",
        "url_matches_the_no_proxy_list_multiple",
        "url_scheme_does_not_match_http_proxy_list",
        "url_scheme_does_not_match_https_proxy_list",
        "no_proxies_are_set",
        "url_is_empty",
    ),
)
@pytest.mark.usefixtures("proxy_env_vars")
def test_get_env_proxy_for_url_negative(url_input: str, expected_err_msg: str) -> None:
    url = URL(url_input)
    with pytest.raises(LookupError, match=expected_err_msg):
        helpers.get_env_proxy_for_url(url)


@pytest.mark.parametrize(
    ("proxy_env_vars", "url_input"),
    (
        ({"http_proxy": "http://example.com"}, "http://aiohttp.io/path"),
        ({"https_proxy": "http://example.com"}, "https://aiohttp.io/path"),
        (
            {"http_proxy": "http://example.com,http://proxy.org"},
            "http://aiohttp.io/path",
        ),
    ),
    indirect=["proxy_env_vars"],
    ids=(
        "url_scheme_match_http_proxy_list",
        "url_scheme_match_https_proxy_list",
        "url_scheme_match_http_proxy_list_multiple",
    ),
)
def test_get_env_proxy_for_url(proxy_env_vars: Dict[str, str], url_input: str) -> None:
    url = URL(url_input)
    proxy, proxy_auth = helpers.get_env_proxy_for_url(url)
    proxy_list = proxy_env_vars[url.scheme + "_proxy"]
    assert proxy == URL(proxy_list)
    assert proxy_auth is None


# ------------- set_result / set_exception ----------------------


async def test_set_result(loop: asyncio.AbstractEventLoop) -> None:
    fut = loop.create_future()
    helpers.set_result(fut, 123)
    assert 123 == await fut


async def test_set_result_cancelled(loop: asyncio.AbstractEventLoop) -> None:
    fut = loop.create_future()
    fut.cancel()
    helpers.set_result(fut, 123)

    with pytest.raises(asyncio.CancelledError):
        await fut


async def test_set_exception(loop: asyncio.AbstractEventLoop) -> None:
    fut = loop.create_future()
    helpers.set_exception(fut, RuntimeError())
    with pytest.raises(RuntimeError):
        await fut


async def test_set_exception_cancelled(loop: asyncio.AbstractEventLoop) -> None:
    fut = loop.create_future()
    fut.cancel()
    helpers.set_exception(fut, RuntimeError())

    with pytest.raises(asyncio.CancelledError):
        await fut


# ----------- ChainMapProxy --------------------------

AppKeyDict = Dict[Union[str, web.AppKey[object]], object]


class TestChainMapProxy:
    def test_inheritance(self) -> None:
        with pytest.raises(TypeError):

            class A(helpers.ChainMapProxy):  # type: ignore[misc]
                pass

    def test_getitem(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp["a"] == 2
        assert cp["b"] == 3

    def test_getitem_not_found(self) -> None:
        d: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d])
        with pytest.raises(KeyError):
            cp["b"]

    def test_get(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get("a") == 2

    def test_get_default(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get("c", 4) == 4

    def test_get_non_default(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert cp.get("a", 4) == 2

    def test_len(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert len(cp) == 2

    def test_iter(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert set(cp) == {"a", "b"}

    def test_contains(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        assert "a" in cp
        assert "b" in cp
        assert "c" not in cp

    def test_bool(self) -> None:
        assert helpers.ChainMapProxy([{"a": 1}])
        assert not helpers.ChainMapProxy([{}, {}])
        assert not helpers.ChainMapProxy([])

    def test_repr(self) -> None:
        d1: AppKeyDict = {"a": 2, "b": 3}
        d2: AppKeyDict = {"a": 1}
        cp = helpers.ChainMapProxy([d1, d2])
        expected = f"ChainMapProxy({d1!r}, {d2!r})"
        assert expected == repr(cp)


def test_is_expected_content_type_json_match_exact() -> None:
    expected_ct = "application/json"
    response_ct = "application/json"
    assert is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_json_match_partially() -> None:
    expected_ct = "application/json"
    response_ct = "application/alto-costmap+json"  # mime-type from rfc7285
    assert is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_non_application_json_suffix() -> None:
    expected_ct = "application/json"
    response_ct = "model/gltf+json"  # rfc 6839
    assert is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_non_application_json_private_suffix() -> None:
    expected_ct = "application/json"
    response_ct = "x-foo/bar+json"  # rfc 6839
    assert is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_json_non_lowercase() -> None:
    """Per RFC 2045, media type matching is case insensitive."""
    expected_ct = "application/json"
    response_ct = "Application/JSON"
    assert is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_json_trailing_chars() -> None:
    expected_ct = "application/json"
    response_ct = "application/json-seq"
    assert not is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_non_json_match_exact() -> None:
    expected_ct = "text/javascript"
    response_ct = "text/javascript"
    assert is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


def test_is_expected_content_type_non_json_not_match() -> None:
    expected_ct = "application/json"
    response_ct = "text/plain"
    assert not is_expected_content_type(
        response_content_type=response_ct, expected_content_type=expected_ct
    )


# It's necessary to subclass CookieMixin before using it.
# See the comments on its __slots__.
class CookieImplementation(helpers.CookieMixin):
    pass


def test_cookies_mixin() -> None:
    sut = CookieImplementation()

    assert sut.cookies == {}
    assert str(sut.cookies) == ""

    sut.set_cookie("name", "value")
    assert str(sut.cookies) == "Set-Cookie: name=value; Path=/"
    sut.set_cookie("name", "")
    assert str(sut.cookies) == 'Set-Cookie: name=""; Path=/'
    sut.set_cookie("name", "value")
    assert str(sut.cookies) == "Set-Cookie: name=value; Path=/"

    sut.set_cookie("name", "other_value")
    assert str(sut.cookies) == "Set-Cookie: name=other_value; Path=/"

    sut.cookies["name"] = "another_other_value"
    sut.cookies["name"]["max-age"] = 10
    assert (
        str(sut.cookies) == "Set-Cookie: name=another_other_value; Max-Age=10; Path=/"
    )

    sut.del_cookie("name")
    expected = (
        'Set-Cookie: name=""; '
        "expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/"
    )
    assert str(sut.cookies) == expected
    sut.del_cookie("name")
    assert str(sut.cookies) == expected

    sut.set_cookie("name", "value", domain="local.host")
    expected = "Set-Cookie: name=value; Domain=local.host; Path=/"
    assert str(sut.cookies) == expected


def test_cookies_mixin_path() -> None:
    sut = CookieImplementation()

    assert sut.cookies == {}

    sut.set_cookie("name", "value", path="/some/path")
    assert str(sut.cookies) == "Set-Cookie: name=value; Path=/some/path"
    sut.set_cookie("name", "value", expires="123")
    assert str(sut.cookies) == "Set-Cookie: name=value; expires=123; Path=/"
    sut.set_cookie(
        "name",
        "value",
        domain="example.com",
        path="/home",
        expires="123",
        max_age="10",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    assert (
        str(sut.cookies).lower() == "set-cookie: name=value; "
        "domain=example.com; "
        "expires=123; "
        "httponly; "
        "max-age=10; "
        "path=/home; "
        "samesite=lax; "
        "secure"
    )


@pytest.mark.skipif(sys.version_info < (3, 14), reason="No partitioned support")
def test_cookies_mixin_partitioned() -> None:
    sut = CookieImplementation()

    assert sut.cookies == {}

    sut.set_cookie("name", "value", partitioned=False)
    assert str(sut.cookies) == "Set-Cookie: name=value; Path=/"

    sut.set_cookie("name", "value", partitioned=True)
    assert str(sut.cookies) == "Set-Cookie: name=value; Partitioned; Path=/"


def test_sutonse_cookie__issue_del_cookie() -> None:
    sut = CookieImplementation()

    assert sut.cookies == {}
    assert str(sut.cookies) == ""

    sut.del_cookie("name")
    expected = (
        'Set-Cookie: name=""; '
        "expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/"
    )
    assert str(sut.cookies) == expected


def test_cookie_set_after_del() -> None:
    sut = CookieImplementation()

    sut.del_cookie("name")
    sut.set_cookie("name", "val")
    # check for Max-Age dropped
    expected = "Set-Cookie: name=val; Path=/"
    assert str(sut.cookies) == expected


def test_populate_with_cookies() -> None:
    cookies_mixin = CookieImplementation()
    cookies_mixin.set_cookie("name", "value")
    headers = CIMultiDict[str]()

    helpers.populate_with_cookies(headers, cookies_mixin.cookies)
    assert headers == CIMultiDict({"Set-Cookie": "name=value; Path=/"})


@pytest.mark.parametrize(
    ["value", "expected"],
    [
        # email.utils.parsedate returns None
        pytest.param("xxyyzz", None),
        # datetime.datetime fails with ValueError("year 4446413 is out of range")
        pytest.param("Tue, 08 Oct 4446413 00:56:40 GMT", None),
        # datetime.datetime fails with ValueError("second must be in 0..59")
        pytest.param("Tue, 08 Oct 2000 00:56:80 GMT", None),
        # OK
        pytest.param(
            "Tue, 08 Oct 2000 00:56:40 GMT",
            datetime.datetime(2000, 10, 8, 0, 56, 40, tzinfo=datetime.timezone.utc),
        ),
        # OK (ignore timezone and overwrite to UTC)
        pytest.param(
            "Tue, 08 Oct 2000 00:56:40 +0900",
            datetime.datetime(2000, 10, 8, 0, 56, 40, tzinfo=datetime.timezone.utc),
        ),
    ],
)
def test_parse_http_date(value: str, expected: Optional[datetime.datetime]) -> None:
    assert parse_http_date(value) == expected


@pytest.mark.parametrize(
    ["netrc_contents", "expected_username"],
    [
        (
            "machine example.com login username password pass\n",
            "username",
        ),
    ],
    indirect=("netrc_contents",),
)
@pytest.mark.usefixtures("netrc_contents")
def test_netrc_from_env(expected_username: str) -> None:
    """Test that reading netrc files from env works as expected"""
    netrc_obj = helpers.netrc_from_env()
    assert netrc_obj is not None
    auth = netrc_obj.authenticators("example.com")
    assert auth is not None
    assert auth[0] == expected_username


@pytest.fixture
def protected_dir(tmp_path: Path) -> Iterator[Path]:
    protected_dir = tmp_path / "protected"
    protected_dir.mkdir()
    try:
        protected_dir.chmod(0o600)
        yield protected_dir
    finally:
        protected_dir.rmdir()


def test_netrc_from_home_does_not_raise_if_access_denied(
    protected_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: protected_dir)
    monkeypatch.delenv("NETRC", raising=False)

    helpers.netrc_from_env()


@pytest.mark.parametrize(
    ["netrc_contents", "expected_auth"],
    [
        (
            "machine example.com login username password pass\n",
            helpers.BasicAuth("username", "pass"),
        ),
        (
            "machine example.com account username password pass\n",
            helpers.BasicAuth("username", "pass"),
        ),
        (
            "machine example.com password pass\n",
            helpers.BasicAuth("", "pass"),
        ),
    ],
    indirect=("netrc_contents",),
)
@pytest.mark.usefixtures("netrc_contents")
def test_basicauth_present_in_netrc(  # type: ignore[misc]
    expected_auth: helpers.BasicAuth,
) -> None:
    """Test that netrc file contents are properly parsed into BasicAuth tuples"""
    netrc_obj = helpers.netrc_from_env()

    assert expected_auth == helpers.basicauth_from_netrc(netrc_obj, "example.com")


@pytest.mark.parametrize(
    ["netrc_contents"],
    [
        ("",),
    ],
    indirect=("netrc_contents",),
)
@pytest.mark.usefixtures("netrc_contents")
def test_read_basicauth_from_empty_netrc() -> None:
    """Test that an error is raised if netrc doesn't have an entry for our host"""
    netrc_obj = helpers.netrc_from_env()

    with pytest.raises(
        LookupError, match="No entry for example.com found in the `.netrc` file."
    ):
        helpers.basicauth_from_netrc(netrc_obj, "example.com")


def test_method_must_be_empty_body() -> None:
    """Test that HEAD is the only method that unequivocally must have an empty body."""
    assert "HEAD" in EMPTY_BODY_METHODS
    # CONNECT is only empty on a successful response
    assert "CONNECT" not in EMPTY_BODY_METHODS


def test_should_remove_content_length_is_subset_of_must_be_empty_body() -> None:
    """Test should_remove_content_length is always a subset of must_be_empty_body."""
    assert should_remove_content_length("GET", 101) is True
    assert must_be_empty_body("GET", 101) is True

    assert should_remove_content_length("GET", 102) is True
    assert must_be_empty_body("GET", 102) is True

    assert should_remove_content_length("GET", 204) is True
    assert must_be_empty_body("GET", 204) is True

    assert should_remove_content_length("GET", 204) is True
    assert must_be_empty_body("GET", 204) is True

    assert should_remove_content_length("GET", 200) is False
    assert must_be_empty_body("GET", 200) is False

    assert should_remove_content_length("HEAD", 200) is False
    assert must_be_empty_body("HEAD", 200) is True

    # CONNECT is only empty on a successful response
    assert should_remove_content_length("CONNECT", 200) is True
    assert must_be_empty_body("CONNECT", 200) is True

    assert should_remove_content_length("CONNECT", 201) is True
    assert must_be_empty_body("CONNECT", 201) is True

    assert should_remove_content_length("CONNECT", 300) is False
    assert must_be_empty_body("CONNECT", 300) is False


# ------------------- Cookie parsing tests ----------------------------------


def test_known_attrs_is_superset_of_morsel_reserved() -> None:
    """Test that _COOKIE_KNOWN_ATTRS contains all Morsel._reserved attributes."""
    # Get Morsel._reserved attributes (lowercase)
    morsel_reserved = {attr.lower() for attr in Morsel._reserved}  # type: ignore[attr-defined]

    # _COOKIE_KNOWN_ATTRS should be a superset of morsel_reserved
    assert (
        helpers._COOKIE_KNOWN_ATTRS >= morsel_reserved
    ), f"_COOKIE_KNOWN_ATTRS is missing: {morsel_reserved - helpers._COOKIE_KNOWN_ATTRS}"


def test_bool_attrs_is_superset_of_morsel_flags() -> None:
    """Test that _COOKIE_BOOL_ATTRS contains all Morsel._flags attributes."""
    # Get Morsel._flags attributes (lowercase)
    morsel_flags = {attr.lower() for attr in Morsel._flags}  # type: ignore[attr-defined]

    # _COOKIE_BOOL_ATTRS should be a superset of morsel_flags
    assert (
        helpers._COOKIE_BOOL_ATTRS >= morsel_flags
    ), f"_COOKIE_BOOL_ATTRS is missing: {morsel_flags - helpers._COOKIE_BOOL_ATTRS}"


def test_preserve_morsel_with_coded_value() -> None:
    """Test preserve_morsel_with_coded_value preserves coded_value exactly."""
    # Create a cookie with a coded_value different from value
    cookie: Morsel[str] = Morsel()
    cookie.set("test_cookie", "decoded value", "encoded%20value")

    # Preserve the coded_value
    result = preserve_morsel_with_coded_value(cookie)

    # Check that all values are preserved
    assert result.key == "test_cookie"
    assert result.value == "decoded value"
    assert result.coded_value == "encoded%20value"

    # Should be a different Morsel instance
    assert result is not cookie


def test_preserve_morsel_with_coded_value_no_coded_value() -> None:
    """Test preserve_morsel_with_coded_value when coded_value is same as value."""
    cookie: Morsel[str] = Morsel()
    cookie.set("test_cookie", "simple_value", "simple_value")

    result = preserve_morsel_with_coded_value(cookie)

    assert result.key == "test_cookie"
    assert result.value == "simple_value"
    assert result.coded_value == "simple_value"


def test_parse_cookie_headers_simple() -> None:
    """Test parse_cookie_headers with simple cookies."""
    headers = ["name=value", "session=abc123"]

    result = parse_cookie_headers(headers)

    assert len(result) == 2
    assert result[0][0] == "name"
    assert result[0][1].key == "name"
    assert result[0][1].value == "value"
    assert result[1][0] == "session"
    assert result[1][1].key == "session"
    assert result[1][1].value == "abc123"


def test_parse_cookie_headers_with_attributes() -> None:
    """Test parse_cookie_headers with cookie attributes."""
    headers = [
        "sessionid=value123; Path=/; HttpOnly; Secure",
        "user=john; Domain=.example.com; Max-Age=3600",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 2

    # First cookie
    name1, morsel1 = result[0]
    assert name1 == "sessionid"
    assert morsel1.value == "value123"
    assert morsel1["path"] == "/"
    assert morsel1["httponly"] is True
    assert morsel1["secure"] is True

    # Second cookie
    name2, morsel2 = result[1]
    assert name2 == "user"
    assert morsel2.value == "john"
    assert morsel2["domain"] == ".example.com"
    assert morsel2["max-age"] == "3600"


def test_parse_cookie_headers_special_chars_in_names() -> None:
    """Test parse_cookie_headers accepts special characters in names (#2683)."""
    # These should be accepted with relaxed validation
    headers = [
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}=value1",
        "cookie[index]=value2",
        "cookie(param)=value3",
        "cookie:name=value4",
        "cookie@domain=value5",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 5
    expected_names = [
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}",
        "cookie[index]",
        "cookie(param)",
        "cookie:name",
        "cookie@domain",
    ]

    for i, (name, morsel) in enumerate(result):
        assert name == expected_names[i]
        assert morsel.key == expected_names[i]
        assert morsel.value == f"value{i+1}"


def test_parse_cookie_headers_invalid_names() -> None:
    """Test parse_cookie_headers rejects truly invalid cookie names."""
    # These should be rejected even with relaxed validation
    headers = [
        "invalid\tcookie=value",  # Tab character
        "invalid\ncookie=value",  # Newline
        "invalid\rcookie=value",  # Carriage return
        "\x00badname=value",  # Null character
        "name with spaces=value",  # Spaces in name
    ]

    result = parse_cookie_headers(headers)

    # All should be skipped
    assert len(result) == 0


def test_parse_cookie_headers_empty_and_invalid() -> None:
    """Test parse_cookie_headers handles empty and invalid formats."""
    headers = [
        "",  # Empty header
        "   ",  # Whitespace only
        "=value",  # No name
        "name=",  # Empty value (should be accepted)
        "justname",  # No value (should be skipped)
        "path=/",  # Reserved attribute as name (should be skipped)
        "Domain=.com",  # Reserved attribute as name (should be skipped)
    ]

    result = parse_cookie_headers(headers)

    # Only "name=" should be accepted
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1].value == ""


def test_parse_cookie_headers_quoted_values() -> None:
    """Test parse_cookie_headers handles quoted values correctly."""
    headers = [
        'name="quoted value"',
        'session="with;semicolon"',
        'data="with\\"escaped\\""',
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3
    assert result[0][1].value == "quoted value"
    assert result[1][1].value == "with;semicolon"
    assert result[2][1].value == 'with"escaped"'


def test_parse_cookie_headers_semicolon_in_quoted_values() -> None:
    """Test that semicolons inside properly quoted values are handled correctly.

    Cookie values can contain semicolons when properly quoted. This test ensures
    that our parser handles these cases correctly, matching SimpleCookie behavior.
    """
    # Test various cases of semicolons in quoted values
    headers = [
        'session="abc;xyz"; token=123',
        'data="value;with;multiple;semicolons"; next=cookie',
        'complex="a=b;c=d"; simple=value',
    ]

    for header in headers:
        # Test with SimpleCookie
        sc = SimpleCookie()
        sc.load(header)

        # Test with our parser
        result = parse_cookie_headers([header])

        # Should parse the same number of cookies
        assert len(result) == len(sc)

        # Verify each cookie matches SimpleCookie
        for (name, morsel), (sc_name, sc_morsel) in zip(result, sc.items()):
            assert name == sc_name
            assert morsel.value == sc_morsel.value


def test_parse_cookie_headers_multiple_cookies_same_header() -> None:
    """Test parse_cookie_headers with multiple cookies in one header."""
    # Note: SimpleCookie includes the comma as part of the first cookie's value
    headers = ["cookie1=value1, cookie2=value2"]

    result = parse_cookie_headers(headers)

    # Should parse as two separate cookies
    assert len(result) == 2
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1,"  # Comma is included in the value
    assert result[1][0] == "cookie2"
    assert result[1][1].value == "value2"


@pytest.mark.parametrize(
    "header",
    [
        # Standard cookies
        "session=abc123",
        "user=john; Path=/",
        "token=xyz; Secure; HttpOnly",
        # Empty values
        "empty=",
        # Quoted values
        'quoted="value with spaces"',
        # Multiple attributes
        "complex=value; Domain=.example.com; Path=/app; Max-Age=3600",
    ],
)
def test_parse_cookie_headers_compatibility_with_simple_cookie(header: str) -> None:
    """Test parse_cookie_headers is bug-for-bug compatible with SimpleCookie.load."""
    # Parse with SimpleCookie
    sc = SimpleCookie()
    sc.load(header)

    # Parse with our function
    result = parse_cookie_headers([header])

    # Should have same number of cookies
    assert len(result) == len(sc)

    # Compare each cookie
    for name, morsel in result:
        assert name in sc
        sc_morsel = sc[name]

        # Compare values
        assert morsel.value == sc_morsel.value
        assert morsel.key == sc_morsel.key

        # Compare attributes (only those that SimpleCookie would set)
        for attr in ["path", "domain", "max-age"]:
            if sc_morsel.get(attr) is not None:
                assert morsel.get(attr) == sc_morsel.get(attr)

        # Boolean attributes are handled differently
        # SimpleCookie sets them to empty string when not present, True when present
        for bool_attr in ["secure", "httponly"]:
            # Only check if SimpleCookie has the attribute set to True
            if sc_morsel.get(bool_attr) is True:
                assert morsel.get(bool_attr) is True


def test_parse_cookie_headers_relaxed_validation_differences() -> None:
    """Test where parse_cookie_headers differs from SimpleCookie (relaxed validation)."""
    # Test cookies that SimpleCookie rejects with CookieError
    rejected_by_simplecookie = [
        ("cookie{with}braces=value1", "cookie{with}braces", "value1"),
        ("cookie(with)parens=value3", "cookie(with)parens", "value3"),
        ("cookie@with@at=value5", "cookie@with@at", "value5"),
    ]

    for header, expected_name, expected_value in rejected_by_simplecookie:
        # SimpleCookie should reject these with CookieError
        sc = SimpleCookie()
        with pytest.raises(CookieError):
            sc.load(header)

        # Our parser should accept them
        result = parse_cookie_headers([header])
        assert len(result) == 1  # We accept
        assert result[0][0] == expected_name
        assert result[0][1].value == expected_value

    # Test cookies that SimpleCookie accepts (but we handle more consistently)
    accepted_by_simplecookie = [
        ("cookie[with]brackets=value2", "cookie[with]brackets", "value2"),
        ("cookie:with:colons=value4", "cookie:with:colons", "value4"),
    ]

    for header, expected_name, expected_value in accepted_by_simplecookie:
        # SimpleCookie accepts these
        sc = SimpleCookie()
        sc.load(header)
        # May or may not parse correctly in SimpleCookie

        # Our parser should accept them consistently
        result = parse_cookie_headers([header])
        assert len(result) == 1
        assert result[0][0] == expected_name
        assert result[0][1].value == expected_value


def test_parse_cookie_headers_case_insensitive_attrs() -> None:
    """Test that known attributes are handled case-insensitively."""
    headers = [
        "cookie1=value1; PATH=/test; DOMAIN=example.com",
        "cookie2=value2; Secure; HTTPONLY; max-AGE=60",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 2

    # First cookie - attributes should be recognized despite case
    assert result[0][1]["path"] == "/test"
    assert result[0][1]["domain"] == "example.com"

    # Second cookie
    assert result[1][1]["secure"] is True
    assert result[1][1]["httponly"] is True
    assert result[1][1]["max-age"] == "60"


def test_parse_cookie_headers_unknown_attrs_ignored() -> None:
    """Test that unknown attributes are treated as new cookies (same as SimpleCookie)."""
    headers = [
        "cookie=value; Path=/; unknownattr=ignored; HttpOnly",
    ]

    result = parse_cookie_headers(headers)

    # SimpleCookie treats unknown attributes with values as new cookies
    assert len(result) == 2

    # First cookie
    assert result[0][0] == "cookie"
    assert result[0][1]["path"] == "/"
    assert result[0][1]["httponly"] == ""  # Not set on first cookie

    # Second cookie (the unknown attribute)
    assert result[1][0] == "unknownattr"
    assert result[1][1].value == "ignored"
    assert result[1][1]["httponly"] is True  # HttpOnly applies to this cookie


def test_parse_cookie_headers_complex_real_world() -> None:
    """Test parse_cookie_headers with complex real-world examples."""
    headers = [
        # AWS ELB cookie
        "AWSELB=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890; Path=/",
        # Google Analytics
        "_ga=GA1.2.1234567890.1234567890; Domain=.example.com; Path=/; Expires=Thu, 31-Dec-2025 23:59:59 GMT",
        # Session with all attributes
        "session_id=s%3AabcXYZ123.signature123; Path=/; Secure; HttpOnly; SameSite=Strict",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3

    # Check each cookie parsed correctly
    assert result[0][0] == "AWSELB"
    assert result[1][0] == "_ga"
    assert result[2][0] == "session_id"

    # Session cookie should have all attributes
    session_morsel = result[2][1]
    assert session_morsel["secure"] is True
    assert session_morsel["httponly"] is True
    assert session_morsel.get("samesite") == "Strict"


def test_parse_cookie_headers_boolean_attrs() -> None:
    """Test that boolean attributes (secure, httponly, partitioned) work correctly."""
    headers = [
        "cookie1=value1; Secure",
        "cookie2=value2; Secure=",
        "cookie3=value3; Secure=true",  # Non-standard but might occur
        "cookie4=value4; HttpOnly",
        "cookie5=value5; HttpOnly=",
    ]

    result = parse_cookie_headers(headers)

    # All should have the boolean attributes set
    assert len(result) == 5
    for i, (_, morsel) in enumerate(result):
        if i < 3:
            assert morsel.get("secure") is True, f"Cookie {i+1} should have secure=True"
        else:
            assert (
                morsel.get("httponly") is True
            ), f"Cookie {i+1} should have httponly=True"


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="Test for Python < 3.14")
def test_parse_cookie_headers_boolean_attrs_with_partitioned_pre_314() -> None:
    """Test that boolean attributes including partitioned work correctly on Python < 3.14."""
    # Create patched reserved and flags with partitioned support
    patched_reserved = Morsel._reserved.copy()
    patched_reserved["partitioned"] = "partitioned"

    patched_flags = Morsel._flags.copy()
    patched_flags.add("partitioned")

    with (
        mock.patch.object(Morsel, "_reserved", patched_reserved),
        mock.patch.object(Morsel, "_flags", patched_flags),
    ):

        headers = [
            "cookie1=value1; Secure",
            "cookie2=value2; Secure=",
            "cookie3=value3; Secure=true",  # Non-standard but might occur
            "cookie4=value4; HttpOnly",
            "cookie5=value5; HttpOnly=",
            "cookie6=value6; Partitioned",
            "cookie7=value7; Partitioned=",
            "cookie8=value8; Partitioned=yes",  # Non-standard but might occur
        ]

        result = parse_cookie_headers(headers)

        # All should have the boolean attributes set
        assert len(result) == 8
        for i, (name, morsel) in enumerate(result):
            if i < 3:
                assert (
                    morsel.get("secure") is True
                ), f"Cookie {i+1} should have secure=True"
            elif i < 5:
                assert (
                    morsel.get("httponly") is True
                ), f"Cookie {i+1} should have httponly=True"
            else:
                assert (
                    morsel.get("partitioned") is True
                ), f"Cookie {i+1} should have partitioned=True"


@pytest.mark.skipif(sys.version_info < (3, 14), reason="Requires Python 3.14+")
def test_parse_cookie_headers_boolean_attrs_with_partitioned() -> None:
    """Test that boolean attributes including partitioned work correctly on Python 3.14+."""
    # Test secure attribute variations
    secure_headers = [
        "cookie1=value1; Secure",
        "cookie2=value2; Secure=",
        "cookie3=value3; Secure=true",  # Non-standard but might occur
    ]

    # Test httponly attribute variations
    httponly_headers = [
        "cookie4=value4; HttpOnly",
        "cookie5=value5; HttpOnly=",
    ]

    # Test partitioned attribute variations
    partitioned_headers = [
        "cookie6=value6; Partitioned",
        "cookie7=value7; Partitioned=",
        "cookie8=value8; Partitioned=yes",  # Non-standard but might occur
    ]

    headers = secure_headers + httponly_headers + partitioned_headers
    result = parse_cookie_headers(headers)

    assert len(result) == 8

    # Check secure cookies
    for i in range(3):
        name, morsel = result[i]
        assert name == f"cookie{i+1}"
        assert morsel.get("secure") is True, f"{name} should have secure=True"

    # Check httponly cookies
    for i in range(3, 5):
        name, morsel = result[i]
        assert name == f"cookie{i+1}"
        assert morsel.get("httponly") is True, f"{name} should have httponly=True"

    # Check partitioned cookies
    for i in range(5, 8):
        name, morsel = result[i]
        assert name == f"cookie{i+1}"
        assert morsel.get("partitioned") is True, f"{name} should have partitioned=True"


def test_parse_cookie_headers_encoded_values() -> None:
    """Test that parse_cookie_headers preserves encoded values."""
    headers = [
        "encoded=hello%20world",
        "url=https%3A%2F%2Fexample.com%2Fpath",
        "special=%21%40%23%24%25%5E%26*%28%29",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3
    # Values should be preserved as-is (not decoded)
    assert result[0][1].value == "hello%20world"
    assert result[1][1].value == "https%3A%2F%2Fexample.com%2Fpath"
    assert result[2][1].value == "%21%40%23%24%25%5E%26*%28%29"


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="Test for Python < 3.14")
def test_parse_cookie_headers_partitioned_pre_314() -> None:
    """
    Test that parse_cookie_headers handles partitioned attribute correctly on Python < 3.14.

    This tests the fix for issue #10380 - partitioned cookies support.
    The partitioned attribute is a boolean flag like secure and httponly.

    On Python < 3.14, this test demonstrates that aiohttp's parser can handle
    partitioned cookies even though Python's SimpleCookie doesn't natively support them.
    """
    # Create patched reserved and flags with partitioned support
    patched_reserved = Morsel._reserved.copy()
    patched_reserved["partitioned"] = "partitioned"

    patched_flags = Morsel._flags.copy()
    patched_flags.add("partitioned")

    with (
        mock.patch.object(Morsel, "_reserved", patched_reserved),
        mock.patch.object(Morsel, "_flags", patched_flags),
    ):

        headers = [
            "cookie1=value1; Partitioned",
            "cookie2=value2; Partitioned=",
            "cookie3=value3; Partitioned=true",  # Non-standard but might occur
            "cookie4=value4; Secure; Partitioned; HttpOnly",
            "cookie5=value5; Domain=.example.com; Path=/; Partitioned",
        ]

        result = parse_cookie_headers(headers)

        assert len(result) == 5

        # All cookies should have partitioned=True
        for i, (name, morsel) in enumerate(result):
            assert (
                morsel.get("partitioned") is True
            ), f"Cookie {i+1} should have partitioned=True"
            assert name == f"cookie{i+1}"
            assert morsel.value == f"value{i+1}"

        # Cookie 4 should also have secure and httponly
        assert result[3][1].get("secure") is True
        assert result[3][1].get("httponly") is True

        # Cookie 5 should also have domain and path
        assert result[4][1].get("domain") == ".example.com"
        assert result[4][1].get("path") == "/"


@pytest.mark.skipif(sys.version_info < (3, 14), reason="Requires Python 3.14+")
def test_parse_cookie_headers_partitioned() -> None:
    """
    Test that parse_cookie_headers handles partitioned attribute correctly on Python 3.14+.

    This tests the fix for issue #10380 - partitioned cookies support.
    The partitioned attribute is a boolean flag like secure and httponly.
    """
    headers = [
        "cookie1=value1; Partitioned",
        "cookie2=value2; Partitioned=",
        "cookie3=value3; Partitioned=true",  # Non-standard but might occur
        "cookie4=value4; Secure; Partitioned; HttpOnly",
        "cookie5=value5; Domain=.example.com; Path=/; Partitioned",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 5

    # All cookies should have partitioned=True
    for i, (name, morsel) in enumerate(result):
        assert (
            morsel.get("partitioned") is True
        ), f"Cookie {i+1} should have partitioned=True"
        assert name == f"cookie{i+1}"
        assert morsel.value == f"value{i+1}"

    # Cookie 4 should also have secure and httponly
    assert result[3][1].get("secure") is True
    assert result[3][1].get("httponly") is True

    # Cookie 5 should also have domain and path
    assert result[4][1].get("domain") == ".example.com"
    assert result[4][1].get("path") == "/"


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="Test for Python < 3.14")
def test_parse_cookie_headers_partitioned_case_insensitive_pre_314() -> None:
    """Test that partitioned attribute is recognized case-insensitively on Python < 3.14."""
    # Create patched reserved and flags with partitioned support
    patched_reserved = Morsel._reserved.copy()
    patched_reserved["partitioned"] = "partitioned"

    patched_flags = Morsel._flags.copy()
    patched_flags.add("partitioned")

    with (
        mock.patch.object(Morsel, "_reserved", patched_reserved),
        mock.patch.object(Morsel, "_flags", patched_flags),
    ):

        headers = [
            "cookie1=value1; partitioned",  # lowercase
            "cookie2=value2; PARTITIONED",  # uppercase
            "cookie3=value3; Partitioned",  # title case
            "cookie4=value4; PaRtItIoNeD",  # mixed case
        ]

        result = parse_cookie_headers(headers)

        assert len(result) == 4

        # All should be recognized as partitioned
        for i, (_, morsel) in enumerate(result):
            assert (
                morsel.get("partitioned") is True
            ), f"Cookie {i+1} should have partitioned=True"


@pytest.mark.skipif(sys.version_info < (3, 14), reason="Requires Python 3.14+")
def test_parse_cookie_headers_partitioned_case_insensitive() -> None:
    """Test that partitioned attribute is recognized case-insensitively on Python 3.14+."""
    headers = [
        "cookie1=value1; partitioned",  # lowercase
        "cookie2=value2; PARTITIONED",  # uppercase
        "cookie3=value3; Partitioned",  # title case
        "cookie4=value4; PaRtItIoNeD",  # mixed case
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 4

    # All should be recognized as partitioned
    for i, (_, morsel) in enumerate(result):
        assert (
            morsel.get("partitioned") is True
        ), f"Cookie {i+1} should have partitioned=True"


def test_parse_cookie_headers_partitioned_not_set() -> None:
    """Test that cookies without partitioned attribute don't have it set."""
    headers = [
        "normal=value; Secure; HttpOnly",
        "regular=cookie; Path=/",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 2

    # Check that partitioned is not set (empty string is the default for flags in Morsel)
    assert result[0][1].get("partitioned", "") == ""
    assert result[1][1].get("partitioned", "") == ""


# Tests that don't require partitioned support in SimpleCookie
def test_parse_cookie_headers_partitioned_with_other_attrs_manual() -> None:
    """
    Test parsing logic for partitioned cookies combined with all other attributes.

    This test verifies our parsing logic handles partitioned correctly as a boolean
    attribute regardless of SimpleCookie support.
    """
    # Test that our parser recognizes partitioned in _COOKIE_KNOWN_ATTRS and _COOKIE_BOOL_ATTRS
    assert "partitioned" in helpers._COOKIE_KNOWN_ATTRS
    assert "partitioned" in helpers._COOKIE_BOOL_ATTRS

    # Test a simple case that won't trigger SimpleCookie errors
    headers = ["session=abc123; Secure; HttpOnly"]
    result = parse_cookie_headers(headers)

    assert len(result) == 1
    assert result[0][0] == "session"
    assert result[0][1]["secure"] is True
    assert result[0][1]["httponly"] is True


def test_parse_cookie_headers_partitioned_real_world_structure() -> None:
    """
    Test real-world partitioned cookie structure without using SimpleCookie.

    This verifies our parsing logic correctly identifies partitioned as a known
    boolean attribute.
    """
    # Test our constants include partitioned
    assert "partitioned" in helpers._COOKIE_KNOWN_ATTRS
    assert "partitioned" in helpers._COOKIE_BOOL_ATTRS

    # Verify the pattern would match partitioned attributes
    pattern = helpers._COOKIE_PATTERN

    # Test various partitioned formats
    test_strings = [
        " Partitioned ",
        " partitioned ",
        " PARTITIONED ",
        " Partitioned; ",
        " Partitioned= ",
        " Partitioned=true ",
    ]

    for test_str in test_strings:
        match = pattern.match(test_str)
        assert match is not None, f"Pattern should match '{test_str}'"
        assert match.group("key").lower() == "partitioned"


def test_parse_cookie_headers_issue_7993_double_quotes() -> None:
    """
    Test that cookies with unmatched opening quotes don't break parsing of subsequent cookies.

    This reproduces issue #7993 where a cookie containing an unmatched opening double quote
    causes subsequent cookies to be silently dropped.

    NOTE: This only fixes the specific case where a value starts with a quote but doesn't
    end with one (e.g., 'cookie="value'). Other malformed quote cases still behave like
    SimpleCookie for compatibility.
    """
    # Test case from the issue
    headers = ['foo=bar; baz="qux; foo2=bar2']

    result = parse_cookie_headers(headers)

    # Should parse all cookies correctly
    assert len(result) == 3
    assert result[0][0] == "foo"
    assert result[0][1].value == "bar"
    assert result[1][0] == "baz"
    assert result[1][1].value == '"qux'  # Unmatched quote included
    assert result[2][0] == "foo2"
    assert result[2][1].value == "bar2"


def test_parse_cookie_headers_unmatched_quotes_compatibility() -> None:
    """Test that most unmatched quote scenarios behave like SimpleCookie.

    For compatibility, we only handle the specific case of unmatched opening quotes
    (e.g., 'cookie="value'). Other cases behave the same as SimpleCookie.
    """
    # Cases that SimpleCookie and our parser both fail to parse completely
    incompatible_cases = [
        'cookie1=val"ue; cookie2=value2',  # codespell:ignore
        'cookie1=value"; cookie2=value2',
        'cookie1=va"l"ue"; cookie2=value2',  # codespell:ignore
        'cookie1=value1; cookie2=val"ue; cookie3=value3',  # codespell:ignore
    ]

    for header in incompatible_cases:
        # Test SimpleCookie behavior
        sc = SimpleCookie()
        sc.load(header)
        sc_cookies = list(sc.items())

        # Test our parser behavior
        result = parse_cookie_headers([header])

        # Both should parse the same cookies (partial parsing)
        assert len(result) == len(sc_cookies), (
            f"Header: {header}\n"
            f"SimpleCookie parsed: {len(sc_cookies)} cookies\n"
            f"Our parser parsed: {len(result)} cookies"
        )

    # The case we specifically fix (unmatched opening quote)
    fixed_case = 'cookie1=value1; cookie2="unmatched; cookie3=value3'

    # SimpleCookie fails to parse cookie3
    sc = SimpleCookie()
    sc.load(fixed_case)
    assert len(sc) == 1  # Only cookie1

    # Our parser handles it better
    result = parse_cookie_headers([fixed_case])
    assert len(result) == 3  # All three cookies
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1"
    assert result[1][0] == "cookie2"
    assert result[1][1].value == '"unmatched'
    assert result[2][0] == "cookie3"
    assert result[2][1].value == "value3"
