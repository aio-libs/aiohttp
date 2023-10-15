import collections
import re
from traceback import format_exception
from unittest import mock

import aiosignal
import pytest
from yarl import URL

from aiohttp import helpers, web
from aiohttp.pytest_plugin import AiohttpClient
from aiohttp.test_utils import make_mocked_request


@pytest.fixture
def buf() -> bytearray:
    return bytearray()


@pytest.fixture
def http_request(buf):
    method = "GET"
    path = "/"
    writer = mock.Mock()
    writer.drain.return_value = ()

    def append(data=b""):
        buf.extend(data)
        return helpers.noop()

    async def write_headers(status_line, headers):
        headers = (
            status_line
            + "\r\n"
            + "".join([k + ": " + v + "\r\n" for k, v in headers.items()])
        )
        headers = headers.encode("utf-8") + b"\r\n"
        buf.extend(headers)

    writer.buffer_data.side_effect = append
    writer.write.side_effect = append
    writer.write_eof.side_effect = append
    writer.write_headers.side_effect = write_headers

    app = mock.Mock()
    app._debug = False
    app.on_response_prepare = aiosignal.Signal(app)
    app.on_response_prepare.freeze()
    req = make_mocked_request(method, path, app=app, writer=writer)
    return req


def test_all_http_exceptions_exported() -> None:
    assert "HTTPException" in web.__all__
    for name in dir(web):
        if name.startswith("_"):
            continue
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            assert name in web.__all__


async def test_HTTPOk(buf, http_request) -> None:
    resp = web.HTTPOk()
    await resp.prepare(http_request)
    await resp.write_eof()
    txt = buf.decode("utf8")
    assert re.match(
        (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: 7\r\n"
            "Date: .+\r\n"
            "Server: .+\r\n\r\n"
            "200: OK"
        ),
        txt,
    )


def test_terminal_classes_has_status_code() -> None:
    terminals = set()
    for name in dir(web):
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            terminals.add(obj)

    dup = frozenset(terminals)
    for cls1 in dup:
        for cls2 in dup:
            if cls1 in cls2.__bases__:
                terminals.discard(cls1)

    for cls in terminals:
        assert cls.status_code is not None
    codes = collections.Counter(cls.status_code for cls in terminals)
    assert None not in codes
    assert 1 == codes.most_common(1)[0][1]


async def test_HTTPFound(buf, http_request) -> None:
    resp = web.HTTPFound(location="/redirect")
    assert "/redirect" == resp.location
    assert "/redirect" == resp.headers["location"]
    await resp.prepare(http_request)
    await resp.write_eof()
    txt = buf.decode("utf8")
    assert re.match(
        "HTTP/1.1 302 Found\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Location: /redirect\r\n"
        "Content-Length: 10\r\n"
        "Date: .+\r\n"
        "Server: .+\r\n\r\n"
        "302: Found",
        txt,
    )


def test_HTTPFound_empty_location() -> None:
    with pytest.raises(ValueError):
        web.HTTPFound(location="")

    with pytest.raises(ValueError):
        web.HTTPFound(location=None)


def test_HTTPFound_location_CRLF() -> None:
    exc = web.HTTPFound(location="/redirect\r\n")
    assert "\r\n" not in exc.headers["Location"]


async def test_HTTPMethodNotAllowed(buf, http_request) -> None:
    resp = web.HTTPMethodNotAllowed("get", ["POST", "PUT"])
    assert "GET" == resp.method
    assert {"POST", "PUT"} == resp.allowed_methods
    assert "POST,PUT" == resp.headers["allow"]
    await resp.prepare(http_request)
    await resp.write_eof()
    txt = buf.decode("utf8")
    assert re.match(
        "HTTP/1.1 405 Method Not Allowed\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Allow: POST,PUT\r\n"
        "Content-Length: 23\r\n"
        "Date: .+\r\n"
        "Server: .+\r\n\r\n"
        "405: Method Not Allowed",
        txt,
    )


def test_override_body_with_text() -> None:
    resp = web.HTTPNotFound(text="Page not found")
    assert 404 == resp.status
    assert b"Page not found" == resp.body
    assert "Page not found" == resp.text
    assert "text/plain" == resp.content_type
    assert "utf-8" == resp.charset


def test_override_body_with_binary() -> None:
    txt = "<html><body>Page not found</body></html>"
    with pytest.warns(DeprecationWarning):
        resp = web.HTTPNotFound(body=txt.encode("utf-8"), content_type="text/html")
    assert 404 == resp.status
    assert txt.encode("utf-8") == resp.body
    assert txt == resp.text
    assert "text/html" == resp.content_type
    assert resp.charset is None


def test_default_body() -> None:
    resp = web.HTTPOk()
    assert b"200: OK" == resp.body


def test_empty_body_204() -> None:
    resp = web.HTTPNoContent()
    assert resp.body is None


def test_empty_body_205() -> None:
    resp = web.HTTPNoContent()
    assert resp.body is None


def test_empty_body_304() -> None:
    resp = web.HTTPNoContent()
    resp.body is None


def test_no_link_451() -> None:
    with pytest.raises(TypeError):
        web.HTTPUnavailableForLegalReasons()  # type: ignore[call-arg]


def test_link_none_451() -> None:
    resp = web.HTTPUnavailableForLegalReasons(link=None)
    assert resp.link is None
    assert "Link" not in resp.headers


def test_link_empty_451() -> None:
    resp = web.HTTPUnavailableForLegalReasons(link="")
    assert resp.link is None
    assert "Link" not in resp.headers


def test_link_str_451() -> None:
    resp = web.HTTPUnavailableForLegalReasons(link="http://warning.or.kr/")
    assert resp.link == URL("http://warning.or.kr/")
    assert resp.headers["Link"] == '<http://warning.or.kr/>; rel="blocked-by"'


def test_link_url_451() -> None:
    resp = web.HTTPUnavailableForLegalReasons(link=URL("http://warning.or.kr/"))
    assert resp.link == URL("http://warning.or.kr/")
    assert resp.headers["Link"] == '<http://warning.or.kr/>; rel="blocked-by"'


def test_link_CRLF_451() -> None:
    resp = web.HTTPUnavailableForLegalReasons(link="http://warning.or.kr/\r\n")
    assert "\r\n" not in resp.headers["Link"]


def test_HTTPException_retains_cause() -> None:
    with pytest.raises(web.HTTPException) as ei:
        try:
            raise Exception("CustomException")
        except Exception as exc:
            raise web.HTTPException() from exc
    tb = "".join(format_exception(ei.type, ei.value, ei.tb))
    assert "CustomException" in tb
    assert "direct cause" in tb


async def test_HTTPException_retains_cookie(aiohttp_client: AiohttpClient) -> None:
    @web.middleware
    async def middleware(request, handler):
        try:
            return await handler(request)
        except web.HTTPException as exc:
            exc.set_cookie("foo", request["foo"])
            raise exc

    async def save(request):
        request["foo"] = "works"
        raise web.HTTPFound("/show")

    async def show(request):
        return web.Response(text=request.cookies["foo"])

    app = web.Application(middlewares=[middleware])
    app.router.add_route("GET", "/save", save)
    app.router.add_route("GET", "/show", show)
    client = await aiohttp_client(app)

    resp = await client.get("/save")
    assert resp.status == 200
    assert str(resp.url)[-5:] == "/show"
    text = await resp.text()
    assert text == "works"


def test_unicode_text_body_unauthorized() -> None:
    """Test that HTTPUnauthorized can be initialized with a string."""
    with pytest.warns(
        DeprecationWarning, match="body argument is deprecated for http web exceptions"
    ):
        resp = web.HTTPUnauthorized(body="text")
    assert resp.status == 401
