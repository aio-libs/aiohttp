# type: ignore
import asyncio
import hashlib
import io
import pathlib
import zlib
from http.cookies import BaseCookie, Morsel, SimpleCookie
from typing import Any
from unittest import mock

import pytest
from multidict import CIMultiDict, CIMultiDictProxy, istr
from yarl import URL

import aiohttp
from aiohttp import BaseConnector, hdrs, payload
from aiohttp.client_reqrep import (
    ClientRequest,
    ClientResponse,
    Fingerprint,
    _gen_default_accept_encoding,
)
from aiohttp.test_utils import make_mocked_coro


@pytest.fixture
def make_request(loop: Any):
    request = None

    def maker(method, url, *args, **kwargs):
        nonlocal request
        request = ClientRequest(method, URL(url), *args, loop=loop, **kwargs)
        return request

    yield maker
    if request is not None:
        loop.run_until_complete(request.close())


@pytest.fixture
def buf():
    return bytearray()


@pytest.fixture
def protocol(loop: Any, transport: Any):
    protocol = mock.Mock()
    protocol.transport = transport
    protocol._drain_helper.return_value = loop.create_future()
    protocol._drain_helper.return_value.set_result(None)
    return protocol


@pytest.fixture
def transport(buf: Any):
    transport = mock.Mock()

    def write(chunk):
        buf.extend(chunk)

    async def write_eof():
        pass

    transport.write.side_effect = write
    transport.write_eof.side_effect = write_eof
    transport.is_closing.return_value = False

    return transport


@pytest.fixture
def conn(transport: Any, protocol: Any):
    return mock.Mock(transport=transport, protocol=protocol)


def test_method1(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")
    assert req.method == "GET"


def test_method2(make_request: Any) -> None:
    req = make_request("head", "http://python.org/")
    assert req.method == "HEAD"


def test_method3(make_request: Any) -> None:
    req = make_request("HEAD", "http://python.org/")
    assert req.method == "HEAD"


def test_version_1_0(make_request: Any) -> None:
    req = make_request("get", "http://python.org/", version="1.0")
    assert req.version == (1, 0)


def test_version_default(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")
    assert req.version == (1, 1)


def test_request_info(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")
    url = URL("http://python.org/")
    assert req.request_info == aiohttp.RequestInfo(url, "GET", req.headers, url)


def test_request_info_with_fragment(make_request: Any) -> None:
    req = make_request("get", "http://python.org/#urlfragment")
    assert req.request_info == aiohttp.RequestInfo(
        URL("http://python.org/"),
        "GET",
        req.headers,
        URL("http://python.org/#urlfragment"),
    )


def test_version_err(make_request: Any) -> None:
    with pytest.raises(ValueError):
        make_request("get", "http://python.org/", version="1.c")


def test_https_proxy(make_request: Any) -> None:
    with pytest.raises(ValueError):
        make_request("get", "http://python.org/", proxy=URL("https://proxy.org"))


def test_keep_alive(make_request: Any) -> None:
    req = make_request("get", "http://python.org/", version=(0, 9))
    assert not req.keep_alive()

    req = make_request("get", "http://python.org/", version=(1, 0))
    assert not req.keep_alive()

    req = make_request(
        "get",
        "http://python.org/",
        version=(1, 0),
        headers={"connection": "keep-alive"},
    )
    assert req.keep_alive()

    req = make_request("get", "http://python.org/", version=(1, 1))
    assert req.keep_alive()

    req = make_request(
        "get", "http://python.org/", version=(1, 1), headers={"connection": "close"}
    )
    assert not req.keep_alive()


def test_host_port_default_http(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")
    assert req.host == "python.org"
    assert req.port == 80
    assert not req.ssl


def test_host_port_default_https(make_request: Any) -> None:
    req = make_request("get", "https://python.org/")
    assert req.host == "python.org"
    assert req.port == 443
    assert req.is_ssl()


def test_host_port_nondefault_http(make_request: Any) -> None:
    req = make_request("get", "http://python.org:960/")
    assert req.host == "python.org"
    assert req.port == 960
    assert not req.is_ssl()


def test_host_port_nondefault_https(make_request: Any) -> None:
    req = make_request("get", "https://python.org:960/")
    assert req.host == "python.org"
    assert req.port == 960
    assert req.is_ssl()


def test_host_port_default_ws(make_request: Any) -> None:
    req = make_request("get", "ws://python.org/")
    assert req.host == "python.org"
    assert req.port == 80
    assert not req.is_ssl()


def test_host_port_default_wss(make_request: Any) -> None:
    req = make_request("get", "wss://python.org/")
    assert req.host == "python.org"
    assert req.port == 443
    assert req.is_ssl()


def test_host_port_nondefault_ws(make_request: Any) -> None:
    req = make_request("get", "ws://python.org:960/")
    assert req.host == "python.org"
    assert req.port == 960
    assert not req.is_ssl()


def test_host_port_nondefault_wss(make_request: Any) -> None:
    req = make_request("get", "wss://python.org:960/")
    assert req.host == "python.org"
    assert req.port == 960
    assert req.is_ssl()


def test_host_port_none_port(make_request: Any) -> None:
    req = make_request("get", "unix://localhost/path")
    assert req.headers["Host"] == "localhost"


def test_host_port_err(make_request: Any) -> None:
    with pytest.raises(ValueError):
        make_request("get", "http://python.org:123e/")


def test_hostname_err(make_request: Any) -> None:
    with pytest.raises(ValueError):
        make_request("get", "http://:8080/")


def test_host_header_host_first(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")
    assert list(req.headers)[0] == "Host"


def test_host_header_host_without_port(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")
    assert req.headers["HOST"] == "python.org"


def test_host_header_host_with_default_port(make_request: Any) -> None:
    req = make_request("get", "http://python.org:80/")
    assert req.headers["HOST"] == "python.org"


def test_host_header_host_with_nondefault_port(make_request: Any) -> None:
    req = make_request("get", "http://python.org:99/")
    assert req.headers["HOST"] == "python.org:99"


def test_host_header_host_idna_encode(make_request: Any) -> None:
    req = make_request("get", "http://xn--9caa.com")
    assert req.headers["HOST"] == "xn--9caa.com"


def test_host_header_host_unicode(make_request: Any) -> None:
    req = make_request("get", "http://éé.com")
    assert req.headers["HOST"] == "xn--9caa.com"


def test_host_header_explicit_host(make_request: Any) -> None:
    req = make_request("get", "http://python.org/", headers={"host": "example.com"})
    assert req.headers["HOST"] == "example.com"


def test_host_header_explicit_host_with_port(make_request: Any) -> None:
    req = make_request("get", "http://python.org/", headers={"host": "example.com:99"})
    assert req.headers["HOST"] == "example.com:99"


def test_host_header_ipv4(make_request: Any) -> None:
    req = make_request("get", "http://127.0.0.2")
    assert req.headers["HOST"] == "127.0.0.2"


def test_host_header_ipv6(make_request: Any) -> None:
    req = make_request("get", "http://[::2]")
    assert req.headers["HOST"] == "[::2]"


def test_host_header_ipv4_with_port(make_request: Any) -> None:
    req = make_request("get", "http://127.0.0.2:99")
    assert req.headers["HOST"] == "127.0.0.2:99"


def test_host_header_ipv6_with_port(make_request: Any) -> None:
    req = make_request("get", "http://[::2]:99")
    assert req.headers["HOST"] == "[::2]:99"


def test_default_headers_useragent(make_request: Any) -> None:
    req = make_request("get", "http://python.org/")

    assert "SERVER" not in req.headers
    assert "USER-AGENT" in req.headers


def test_default_headers_useragent_custom(make_request: Any) -> None:
    req = make_request(
        "get", "http://python.org/", headers={"user-agent": "my custom agent"}
    )

    assert "USER-Agent" in req.headers
    assert "my custom agent" == req.headers["User-Agent"]


def test_skip_default_useragent_header(make_request: Any) -> None:
    req = make_request(
        "get", "http://python.org/", skip_auto_headers={istr("user-agent")}
    )

    assert "User-Agent" not in req.headers


def test_headers(make_request: Any) -> None:
    req = make_request(
        "post", "http://python.org/", headers={"Content-Type": "text/plain"}
    )

    assert "CONTENT-TYPE" in req.headers
    assert req.headers["CONTENT-TYPE"] == "text/plain"
    assert req.headers["ACCEPT-ENCODING"] == "gzip, deflate, br"


def test_headers_list(make_request: Any) -> None:
    req = make_request(
        "post", "http://python.org/", headers=[("Content-Type", "text/plain")]
    )
    assert "CONTENT-TYPE" in req.headers
    assert req.headers["CONTENT-TYPE"] == "text/plain"


def test_headers_default(make_request: Any) -> None:
    req = make_request(
        "get", "http://python.org/", headers={"ACCEPT-ENCODING": "deflate"}
    )
    assert req.headers["ACCEPT-ENCODING"] == "deflate"


def test_invalid_url(make_request: Any) -> None:
    with pytest.raises(aiohttp.InvalidURL):
        make_request("get", "hiwpefhipowhefopw")


def test_no_path(make_request: Any) -> None:
    req = make_request("get", "http://python.org")
    assert "/" == req.url.path


def test_ipv6_default_http_port(make_request: Any) -> None:
    req = make_request("get", "http://[2001:db8::1]/")
    assert req.host == "2001:db8::1"
    assert req.port == 80
    assert not req.ssl


def test_ipv6_default_https_port(make_request: Any) -> None:
    req = make_request("get", "https://[2001:db8::1]/")
    assert req.host == "2001:db8::1"
    assert req.port == 443
    assert req.is_ssl()


def test_ipv6_nondefault_http_port(make_request: Any) -> None:
    req = make_request("get", "http://[2001:db8::1]:960/")
    assert req.host == "2001:db8::1"
    assert req.port == 960
    assert not req.is_ssl()


def test_ipv6_nondefault_https_port(make_request: Any) -> None:
    req = make_request("get", "https://[2001:db8::1]:960/")
    assert req.host == "2001:db8::1"
    assert req.port == 960
    assert req.is_ssl()


def test_basic_auth(make_request: Any) -> None:
    req = make_request(
        "get", "http://python.org", auth=aiohttp.BasicAuth("nkim", "1234")
    )
    assert "AUTHORIZATION" in req.headers
    assert "Basic bmtpbToxMjM0" == req.headers["AUTHORIZATION"]


def test_basic_auth_utf8(make_request: Any) -> None:
    req = make_request(
        "get", "http://python.org", auth=aiohttp.BasicAuth("nkim", "секрет", "utf-8")
    )
    assert "AUTHORIZATION" in req.headers
    assert "Basic bmtpbTrRgdC10LrRgNC10YI=" == req.headers["AUTHORIZATION"]


def test_basic_auth_tuple_forbidden(make_request: Any) -> None:
    with pytest.raises(TypeError):
        make_request("get", "http://python.org", auth=("nkim", "1234"))


def test_basic_auth_from_url(make_request: Any) -> None:
    req = make_request("get", "http://nkim:1234@python.org")
    assert "AUTHORIZATION" in req.headers
    assert "Basic bmtpbToxMjM0" == req.headers["AUTHORIZATION"]
    assert "python.org" == req.host


def test_basic_auth_from_url_overridden(make_request: Any) -> None:
    req = make_request(
        "get", "http://garbage@python.org", auth=aiohttp.BasicAuth("nkim", "1234")
    )
    assert "AUTHORIZATION" in req.headers
    assert "Basic bmtpbToxMjM0" == req.headers["AUTHORIZATION"]
    assert "python.org" == req.host


def test_path_is_not_double_encoded1(make_request: Any) -> None:
    req = make_request("get", "http://0.0.0.0/get/test case")
    assert req.url.raw_path == "/get/test%20case"


def test_path_is_not_double_encoded2(make_request: Any) -> None:
    req = make_request("get", "http://0.0.0.0/get/test%2fcase")
    assert req.url.raw_path == "/get/test%2Fcase"


def test_path_is_not_double_encoded3(make_request: Any) -> None:
    req = make_request("get", "http://0.0.0.0/get/test%20case")
    assert req.url.raw_path == "/get/test%20case"


def test_path_safe_chars_preserved(make_request: Any) -> None:
    req = make_request("get", "http://0.0.0.0/get/:=+/%2B/")
    assert req.url.path == "/get/:=+/+/"


def test_params_are_added_before_fragment1(make_request: Any) -> None:
    req = make_request("GET", "http://example.com/path#fragment", params={"a": "b"})
    assert str(req.url) == "http://example.com/path?a=b"


def test_params_are_added_before_fragment2(make_request: Any) -> None:
    req = make_request(
        "GET", "http://example.com/path?key=value#fragment", params={"a": "b"}
    )
    assert str(req.url) == "http://example.com/path?key=value&a=b"


def test_path_not_contain_fragment1(make_request: Any) -> None:
    req = make_request("GET", "http://example.com/path#fragment")
    assert req.url.path == "/path"


def test_path_not_contain_fragment2(make_request: Any) -> None:
    req = make_request("GET", "http://example.com/path?key=value#fragment")
    assert str(req.url) == "http://example.com/path?key=value"


def test_cookies(make_request: Any) -> None:
    req = make_request("get", "http://test.com/path", cookies={"cookie1": "val1"})

    assert "COOKIE" in req.headers
    assert "cookie1=val1" == req.headers["COOKIE"]


def test_cookies_is_quoted_with_special_characters(make_request: Any) -> None:
    req = make_request("get", "http://test.com/path", cookies={"cookie1": "val/one"})

    assert "COOKIE" in req.headers
    assert 'cookie1="val/one"' == req.headers["COOKIE"]


def test_cookies_merge_with_headers(make_request: Any) -> None:
    req = make_request(
        "get",
        "http://test.com/path",
        headers={"cookie": "cookie1=val1"},
        cookies={"cookie2": "val2"},
    )

    assert "cookie1=val1; cookie2=val2" == req.headers["COOKIE"]


def test_query_multivalued_param(make_request: Any) -> None:
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(
            meth, "http://python.org", params=(("test", "foo"), ("test", "baz"))
        )

        assert str(req.url) == "http://python.org/?test=foo&test=baz"


def test_query_str_param(make_request: Any) -> None:
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(meth, "http://python.org", params="test=foo")
        assert str(req.url) == "http://python.org/?test=foo"


def test_query_bytes_param_raises(make_request: Any) -> None:
    for meth in ClientRequest.ALL_METHODS:
        with pytest.raises(TypeError):
            make_request(meth, "http://python.org", params=b"test=foo")


def test_query_str_param_is_not_encoded(make_request: Any) -> None:
    for meth in ClientRequest.ALL_METHODS:
        req = make_request(meth, "http://python.org", params="test=f+oo")
        assert str(req.url) == "http://python.org/?test=f+oo"


def test_params_update_path_and_url(make_request: Any) -> None:
    req = make_request(
        "get", "http://python.org", params=(("test", "foo"), ("test", "baz"))
    )
    assert str(req.url) == "http://python.org/?test=foo&test=baz"


def test_params_empty_path_and_url(make_request: Any) -> None:
    req_empty = make_request("get", "http://python.org", params={})
    assert str(req_empty.url) == "http://python.org"
    req_none = make_request("get", "http://python.org")
    assert str(req_none.url) == "http://python.org"


def test_gen_netloc_all(make_request: Any) -> None:
    req = make_request(
        "get",
        "https://aiohttp:pwpwpw@"
        + "12345678901234567890123456789"
        + "012345678901234567890:8080",
    )
    assert (
        req.headers["HOST"]
        == "12345678901234567890123456789" + "012345678901234567890:8080"
    )


def test_gen_netloc_no_port(make_request: Any) -> None:
    req = make_request(
        "get",
        "https://aiohttp:pwpwpw@"
        + "12345678901234567890123456789"
        + "012345678901234567890/",
    )
    assert (
        req.headers["HOST"] == "12345678901234567890123456789" + "012345678901234567890"
    )


async def test_connection_header(loop: Any, conn: Any) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    req.keep_alive = mock.Mock()
    req.headers.clear()

    req.keep_alive.return_value = True
    req.version = (1, 1)
    req.headers.clear()
    await req.send(conn)
    assert req.headers.get("CONNECTION") is None

    req.version = (1, 0)
    req.headers.clear()
    await req.send(conn)
    assert req.headers.get("CONNECTION") == "keep-alive"

    req.keep_alive.return_value = False
    req.version = (1, 1)
    req.headers.clear()
    await req.send(conn)
    assert req.headers.get("CONNECTION") == "close"


async def test_no_content_length(loop: Any, conn: Any) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    resp = await req.send(conn)
    assert req.headers.get("CONTENT-LENGTH") is None
    await req.close()
    resp.close()


async def test_no_content_length_head(loop: Any, conn: Any) -> None:
    req = ClientRequest("head", URL("http://python.org"), loop=loop)
    resp = await req.send(conn)
    assert req.headers.get("CONTENT-LENGTH") is None
    await req.close()
    resp.close()


async def test_content_type_auto_header_get(loop: Any, conn: Any) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    resp = await req.send(conn)
    assert "CONTENT-TYPE" not in req.headers
    resp.close()
    await req.close()


async def test_content_type_auto_header_form(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post", URL("http://python.org"), data={"hey": "you"}, loop=loop
    )
    resp = await req.send(conn)
    assert "application/x-www-form-urlencoded" == req.headers.get("CONTENT-TYPE")
    resp.close()


async def test_content_type_auto_header_bytes(loop: Any, conn: Any) -> None:
    req = ClientRequest("post", URL("http://python.org"), data=b"hey you", loop=loop)
    resp = await req.send(conn)
    assert "application/octet-stream" == req.headers.get("CONTENT-TYPE")
    resp.close()


async def test_content_type_skip_auto_header_bytes(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org"),
        data=b"hey you",
        skip_auto_headers={"Content-Type"},
        loop=loop,
    )
    resp = await req.send(conn)
    assert "CONTENT-TYPE" not in req.headers
    resp.close()


async def test_content_type_skip_auto_header_form(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org"),
        data={"hey": "you"},
        loop=loop,
        skip_auto_headers={"Content-Type"},
    )
    resp = await req.send(conn)
    assert "CONTENT-TYPE" not in req.headers
    resp.close()


async def test_content_type_auto_header_content_length_no_skip(
    loop: Any, conn: Any
) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org"),
        data=io.BytesIO(b"hey"),
        skip_auto_headers={"Content-Length"},
        loop=loop,
    )
    resp = await req.send(conn)
    assert req.headers.get("CONTENT-LENGTH") == "3"
    resp.close()


async def test_urlencoded_formdata_charset(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org"),
        data=aiohttp.FormData({"hey": "you"}, charset="koi8-r"),
        loop=loop,
    )
    await req.send(conn)
    assert "application/x-www-form-urlencoded; charset=koi8-r" == req.headers.get(
        "CONTENT-TYPE"
    )


async def test_post_data(loop: Any, conn: Any) -> None:
    for meth in ClientRequest.POST_METHODS:
        req = ClientRequest(
            meth, URL("http://python.org/"), data={"life": "42"}, loop=loop
        )
        resp = await req.send(conn)
        assert "/" == req.url.path
        assert b"life=42" == req.body._value
        assert "application/x-www-form-urlencoded" == req.headers["CONTENT-TYPE"]
        await req.close()
        resp.close()


async def test_pass_falsy_data(loop: Any) -> None:
    with mock.patch("aiohttp.client_reqrep.ClientRequest.update_body_from_data"):
        req = ClientRequest("post", URL("http://python.org/"), data={}, loop=loop)
        req.update_body_from_data.assert_called_once_with({})
    await req.close()


async def test_pass_falsy_data_file(loop: Any, tmp_path: Any) -> None:
    testfile = (tmp_path / "tmpfile").open("w+b")
    testfile.write(b"data")
    testfile.seek(0)
    skip = frozenset([hdrs.CONTENT_TYPE])
    req = ClientRequest(
        "post",
        URL("http://python.org/"),
        data=testfile,
        skip_auto_headers=skip,
        loop=loop,
    )
    assert req.headers.get("CONTENT-LENGTH", None) is not None
    await req.close()
    testfile.close()


# Elasticsearch API requires to send request body with GET-requests
async def test_get_with_data(loop: Any) -> None:
    for meth in ClientRequest.GET_METHODS:
        req = ClientRequest(
            meth, URL("http://python.org/"), data={"life": "42"}, loop=loop
        )
        assert "/" == req.url.path
        assert b"life=42" == req.body._value
        await req.close()


async def test_bytes_data(loop: Any, conn: Any) -> None:
    for meth in ClientRequest.POST_METHODS:
        req = ClientRequest(
            meth, URL("http://python.org/"), data=b"binary data", loop=loop
        )
        resp = await req.send(conn)
        assert "/" == req.url.path
        assert isinstance(req.body, payload.BytesPayload)
        assert b"binary data" == req.body._value
        assert "application/octet-stream" == req.headers["CONTENT-TYPE"]
        await req.close()
        resp.close()


async def test_content_encoding(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post", URL("http://python.org/"), data="foo", compress="deflate", loop=loop
    )
    with mock.patch("aiohttp.client_reqrep.StreamWriter") as m_writer:
        m_writer.return_value.write_headers = make_mocked_coro()
        resp = await req.send(conn)
    assert req.headers["TRANSFER-ENCODING"] == "chunked"
    assert req.headers["CONTENT-ENCODING"] == "deflate"
    m_writer.return_value.enable_compression.assert_called_with("deflate")
    await req.close()
    resp.close()


async def test_content_encoding_dont_set_headers_if_no_body(
    loop: Any, conn: Any
) -> None:
    req = ClientRequest(
        "post", URL("http://python.org/"), compress="deflate", loop=loop
    )
    with mock.patch("aiohttp.client_reqrep.http"):
        resp = await req.send(conn)
    assert "TRANSFER-ENCODING" not in req.headers
    assert "CONTENT-ENCODING" not in req.headers
    await req.close()
    resp.close()


async def test_content_encoding_header(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org/"),
        data="foo",
        headers={"Content-Encoding": "deflate"},
        loop=loop,
    )
    with mock.patch("aiohttp.client_reqrep.StreamWriter") as m_writer:
        m_writer.return_value.write_headers = make_mocked_coro()
        resp = await req.send(conn)

    assert not m_writer.return_value.enable_compression.called
    assert not m_writer.return_value.enable_chunking.called
    await req.close()
    resp.close()


async def test_compress_and_content_encoding(loop: Any, conn: Any) -> None:
    with pytest.raises(ValueError):
        ClientRequest(
            "post",
            URL("http://python.org/"),
            data="foo",
            headers={"content-encoding": "deflate"},
            compress="deflate",
            loop=loop,
        )


async def test_chunked(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org/"),
        headers={"TRANSFER-ENCODING": "gzip"},
        loop=loop,
    )
    resp = await req.send(conn)
    assert "gzip" == req.headers["TRANSFER-ENCODING"]
    await req.close()
    resp.close()


async def test_chunked2(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "post",
        URL("http://python.org/"),
        headers={"Transfer-encoding": "chunked"},
        loop=loop,
    )
    resp = await req.send(conn)
    assert "chunked" == req.headers["TRANSFER-ENCODING"]
    await req.close()
    resp.close()


async def test_chunked_explicit(loop: Any, conn: Any) -> None:
    req = ClientRequest("post", URL("http://python.org/"), chunked=True, loop=loop)
    with mock.patch("aiohttp.client_reqrep.StreamWriter") as m_writer:
        m_writer.return_value.write_headers = make_mocked_coro()
        resp = await req.send(conn)

    assert "chunked" == req.headers["TRANSFER-ENCODING"]
    m_writer.return_value.enable_chunking.assert_called_with()
    await req.close()
    resp.close()


async def test_chunked_length(loop: Any, conn: Any) -> None:
    with pytest.raises(ValueError):
        ClientRequest(
            "post",
            URL("http://python.org/"),
            headers={"CONTENT-LENGTH": "1000"},
            chunked=True,
            loop=loop,
        )


async def test_chunked_transfer_encoding(loop: Any, conn: Any) -> None:
    with pytest.raises(ValueError):
        ClientRequest(
            "post",
            URL("http://python.org/"),
            headers={"TRANSFER-ENCODING": "chunked"},
            chunked=True,
            loop=loop,
        )


async def test_file_upload_not_chunked(loop: Any) -> None:
    file_path = pathlib.Path(__file__).parent / "aiohttp.png"
    with file_path.open("rb") as f:
        req = ClientRequest("post", URL("http://python.org/"), data=f, loop=loop)
        assert not req.chunked
        assert req.headers["CONTENT-LENGTH"] == str(file_path.stat().st_size)
        await req.close()


async def test_precompressed_data_stays_intact(loop: Any) -> None:
    data = zlib.compress(b"foobar")
    req = ClientRequest(
        "post",
        URL("http://python.org/"),
        data=data,
        headers={"CONTENT-ENCODING": "deflate"},
        compress=False,
        loop=loop,
    )
    assert not req.compress
    assert not req.chunked
    assert req.headers["CONTENT-ENCODING"] == "deflate"
    await req.close()


async def test_file_upload_not_chunked_seek(loop: Any) -> None:
    file_path = pathlib.Path(__file__).parent / "aiohttp.png"
    with file_path.open("rb") as f:
        f.seek(100)
        req = ClientRequest("post", URL("http://python.org/"), data=f, loop=loop)
        assert req.headers["CONTENT-LENGTH"] == str(file_path.stat().st_size - 100)
        await req.close()


async def test_file_upload_force_chunked(loop: Any) -> None:
    file_path = pathlib.Path(__file__).parent / "aiohttp.png"
    with file_path.open("rb") as f:
        req = ClientRequest(
            "post", URL("http://python.org/"), data=f, chunked=True, loop=loop
        )
        assert req.chunked
        assert "CONTENT-LENGTH" not in req.headers
        await req.close()


async def test_expect100(loop: Any, conn: Any) -> None:
    req = ClientRequest("get", URL("http://python.org/"), expect100=True, loop=loop)
    resp = await req.send(conn)
    assert "100-continue" == req.headers["EXPECT"]
    assert req._continue is not None
    req.terminate()
    resp.close()


async def test_expect_100_continue_header(loop: Any, conn: Any) -> None:
    req = ClientRequest(
        "get", URL("http://python.org/"), headers={"expect": "100-continue"}, loop=loop
    )
    resp = await req.send(conn)
    assert "100-continue" == req.headers["EXPECT"]
    assert req._continue is not None
    req.terminate()
    resp.close()


async def test_data_stream(loop: Any, buf: Any, conn: Any) -> None:
    async def gen():
        yield b"binary data"
        yield b" result"

    req = ClientRequest("POST", URL("http://python.org/"), data=gen(), loop=loop)
    assert req.chunked
    assert req.headers["TRANSFER-ENCODING"] == "chunked"

    resp = await req.send(conn)
    assert asyncio.isfuture(req._writer)
    await resp.wait_for_close()
    assert req._writer is None
    assert (
        buf.split(b"\r\n\r\n", 1)[1] == b"b\r\nbinary data\r\n7\r\n result\r\n0\r\n\r\n"
    )
    await req.close()


async def test_data_file(loop: Any, buf: Any, conn: Any) -> None:
    req = ClientRequest(
        "POST",
        URL("http://python.org/"),
        data=io.BufferedReader(io.BytesIO(b"*" * 2)),
        loop=loop,
    )
    assert req.chunked
    assert isinstance(req.body, payload.BufferedReaderPayload)
    assert req.headers["TRANSFER-ENCODING"] == "chunked"

    resp = await req.send(conn)
    assert asyncio.isfuture(req._writer)
    await resp.wait_for_close()
    assert req._writer is None
    assert buf.split(b"\r\n\r\n", 1)[1] == b"2\r\n" + b"*" * 2 + b"\r\n0\r\n\r\n"
    await req.close()


async def test_data_stream_exc(loop: Any, conn: Any) -> None:
    fut = loop.create_future()

    async def gen():
        yield b"binary data"
        await fut

    req = ClientRequest("POST", URL("http://python.org/"), data=gen(), loop=loop)
    assert req.chunked
    assert req.headers["TRANSFER-ENCODING"] == "chunked"

    async def throw_exc():
        await asyncio.sleep(0.01)
        fut.set_exception(ValueError)

    loop.create_task(throw_exc())

    await req.send(conn)
    await req._writer
    # assert conn.close.called
    assert conn.protocol.set_exception.called
    await req.close()


async def test_data_stream_exc_chain(loop: Any, conn: Any) -> None:
    fut = loop.create_future()

    async def gen():
        await fut
        return
        yield

    req = ClientRequest("POST", URL("http://python.org/"), data=gen(), loop=loop)

    inner_exc = ValueError()

    async def throw_exc():
        await asyncio.sleep(0.01)
        fut.set_exception(inner_exc)

    loop.create_task(throw_exc())

    await req.send(conn)
    await req._writer
    # assert connection.close.called
    assert conn.protocol.set_exception.called
    outer_exc = conn.protocol.set_exception.call_args[0][0]
    assert isinstance(outer_exc, ValueError)
    assert inner_exc is outer_exc
    assert inner_exc is outer_exc
    await req.close()


async def test_data_stream_continue(loop: Any, buf: Any, conn: Any) -> None:
    async def gen():
        yield b"binary data"
        yield b" result"

    req = ClientRequest(
        "POST", URL("http://python.org/"), data=gen(), expect100=True, loop=loop
    )
    assert req.chunked

    async def coro():
        await asyncio.sleep(0.0001)
        req._continue.set_result(1)

    loop.create_task(coro())

    resp = await req.send(conn)
    await req._writer
    assert (
        buf.split(b"\r\n\r\n", 1)[1] == b"b\r\nbinary data\r\n7\r\n result\r\n0\r\n\r\n"
    )
    await req.close()
    resp.close()


async def test_data_continue(loop: Any, buf: Any, conn: Any) -> None:
    req = ClientRequest(
        "POST", URL("http://python.org/"), data=b"data", expect100=True, loop=loop
    )

    async def coro():
        await asyncio.sleep(0.0001)
        req._continue.set_result(1)

    loop.create_task(coro())

    resp = await req.send(conn)

    await req._writer
    assert buf.split(b"\r\n\r\n", 1)[1] == b"data"
    await req.close()
    resp.close()


async def test_close(loop: Any, buf: Any, conn: Any) -> None:
    async def gen():
        await asyncio.sleep(0.00001)
        yield b"result"

    req = ClientRequest("POST", URL("http://python.org/"), data=gen(), loop=loop)
    resp = await req.send(conn)
    await req.close()
    assert buf.split(b"\r\n\r\n", 1)[1] == b"6\r\nresult\r\n0\r\n\r\n"
    await req.close()
    resp.close()


async def test_custom_response_class(loop: Any, conn: Any) -> None:
    class CustomResponse(ClientResponse):
        def read(self, decode=False):
            return "customized!"

    req = ClientRequest(
        "GET", URL("http://python.org/"), response_class=CustomResponse, loop=loop
    )
    resp = await req.send(conn)
    assert "customized!" == resp.read()
    await req.close()
    resp.close()


async def test_oserror_on_write_bytes(loop: Any, conn: Any) -> None:
    req = ClientRequest("POST", URL("http://python.org/"), loop=loop)

    writer = mock.Mock()
    writer.write.side_effect = OSError

    await req.write_bytes(writer, conn)

    assert conn.protocol.set_exception.called
    exc = conn.protocol.set_exception.call_args[0][0]
    assert isinstance(exc, aiohttp.ClientOSError)


async def test_terminate(loop: Any, conn: Any) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    resp = await req.send(conn)
    assert req._writer is not None
    writer = req._writer = mock.Mock()

    req.terminate()
    assert req._writer is None
    writer.cancel.assert_called_with()
    resp.close()


def test_terminate_with_closed_loop(loop: Any, conn: Any) -> None:
    req = resp = writer = None

    async def go():
        nonlocal req, resp, writer
        req = ClientRequest("get", URL("http://python.org"), loop=loop)
        resp = await req.send(conn)
        assert req._writer is not None
        writer = req._writer = mock.Mock()

        await asyncio.sleep(0.05)

    loop.run_until_complete(go())

    loop.close()
    req.terminate()
    assert req._writer is None
    assert not writer.cancel.called
    resp.close()


def test_terminate_without_writer(loop: Any) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    assert req._writer is None

    req.terminate()
    assert req._writer is None


async def test_custom_req_rep(loop: Any, create_mocked_conn: Any) -> None:
    conn = None

    class CustomResponse(ClientResponse):
        async def start(self, connection, read_until_eof=False):
            nonlocal conn
            conn = connection
            self.status = 123
            self.reason = "Test OK"
            self._headers = CIMultiDictProxy(CIMultiDict())
            self.cookies = SimpleCookie()
            return

    called = False

    class CustomRequest(ClientRequest):
        async def send(self, conn):
            resp = self.response_class(
                self.method,
                self.url,
                writer=self._writer,
                continue100=self._continue,
                timer=self._timer,
                request_info=self.request_info,
                traces=self._traces,
                loop=self.loop,
                session=self._session,
            )
            self.response = resp
            nonlocal called
            called = True
            return resp

    async def create_connection(req, traces, timeout):
        assert isinstance(req, CustomRequest)
        return create_mocked_conn()

    connector = BaseConnector()
    connector._create_connection = create_connection

    session = aiohttp.ClientSession(
        request_class=CustomRequest, response_class=CustomResponse, connector=connector
    )

    resp = await session.request("get", URL("http://example.com/path/to"))
    assert isinstance(resp, CustomResponse)
    assert called
    resp.close()
    await session.close()
    conn.close()


def test_bad_fingerprint(loop: Any) -> None:
    with pytest.raises(ValueError):
        Fingerprint(b"invalid")


def test_insecure_fingerprint_md5(loop: Any) -> None:
    with pytest.raises(ValueError):
        Fingerprint(hashlib.md5(b"foo").digest())


def test_insecure_fingerprint_sha1(loop: Any) -> None:
    with pytest.raises(ValueError):
        Fingerprint(hashlib.sha1(b"foo").digest())


def test_loose_cookies_types(loop: Any) -> None:
    req = ClientRequest("get", URL("http://python.org"), loop=loop)
    morsel = Morsel()
    morsel.set(key="string", val="Another string", coded_val="really")

    accepted_types = [
        [("str", BaseCookie())],
        [("str", morsel)],
        [
            ("str", "str"),
        ],
        {"str": BaseCookie()},
        {"str": morsel},
        {"str": "str"},
        SimpleCookie(),
    ]

    for loose_cookies_type in accepted_types:
        req.update_cookies(cookies=loose_cookies_type)


@pytest.mark.parametrize(
    "has_brotli,expected",
    [
        (False, "gzip, deflate"),
        (True, "gzip, deflate, br"),
    ],
)
def test_gen_default_accept_encoding(has_brotli: Any, expected: Any) -> None:
    with mock.patch("aiohttp.client_reqrep.HAS_BROTLI", has_brotli):
        assert _gen_default_accept_encoding() == expected
