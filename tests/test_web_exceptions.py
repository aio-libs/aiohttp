import collections
import pickle
from traceback import format_exception
from typing import Mapping, NoReturn

import pytest
from yarl import URL

from aiohttp import web
from aiohttp.pytest_plugin import AiohttpClient


def test_all_http_exceptions_exported() -> None:
    assert "HTTPException" in web.__all__
    for name in dir(web):
        if name.startswith("_"):
            continue
        obj = getattr(web, name)
        if isinstance(obj, type) and issubclass(obj, web.HTTPException):
            assert name in web.__all__


async def test_ctor() -> None:
    resp = web.HTTPOk()
    assert resp.text == "200: OK"
    compare: Mapping[str, str] = {"Content-Type": "text/plain"}
    assert resp.headers == compare
    assert resp.reason == "OK"
    assert resp.status == 200
    assert bool(resp)


async def test_ctor_with_headers() -> None:
    resp = web.HTTPOk(headers={"X-Custom": "value"})
    assert resp.text == "200: OK"
    compare: Mapping[str, str] = {"Content-Type": "text/plain", "X-Custom": "value"}
    assert resp.headers == compare
    assert resp.reason == "OK"
    assert resp.status == 200


async def test_ctor_content_type() -> None:
    resp = web.HTTPOk(text="text", content_type="custom")
    assert resp.text == "text"
    compare: Mapping[str, str] = {"Content-Type": "custom"}
    assert resp.headers == compare
    assert resp.reason == "OK"
    assert resp.status == 200
    assert bool(resp)


async def test_ctor_content_type_without_text() -> None:
    with pytest.deprecated_call(
        match=r"^content_type without text is deprecated since "
        r"4\.0 and scheduled for removal in 5\.0 \(#3462\)$",
    ):
        resp = web.HTTPResetContent(content_type="custom")
    assert resp.text is None
    compare: Mapping[str, str] = {"Content-Type": "custom"}
    assert resp.headers == compare
    assert resp.reason == "Reset Content"
    assert resp.status == 205
    assert bool(resp)


async def test_ctor_text_for_empty_body() -> None:
    with pytest.deprecated_call(
        match=r"^text argument is deprecated for HTTP status 205 since "
        r"4\.0 and scheduled for removal in 5\.0 \(#3462\),the "
        r"response should be provided without a body$",
    ):
        resp = web.HTTPResetContent(text="text")
    assert resp.text == "text"
    compare: Mapping[str, str] = {"Content-Type": "text/plain"}
    assert resp.headers == compare
    assert resp.reason == "Reset Content"
    assert resp.status == 205


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


def test_with_text() -> None:
    resp = web.HTTPNotFound(text="Page not found")
    assert 404 == resp.status
    assert "Page not found" == resp.text
    assert "text/plain" == resp.headers["Content-Type"]


def test_default_text() -> None:
    resp = web.HTTPOk()
    assert "200: OK" == resp.text


def test_empty_text_204() -> None:
    resp = web.HTTPNoContent()
    assert resp.text is None


def test_empty_text_205() -> None:
    resp = web.HTTPResetContent()
    assert resp.text is None


def test_empty_text_304() -> None:
    resp = web.HTTPNoContent()
    resp.text is None


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


class TestHTTPOk:
    def test_ctor_all(self) -> None:
        resp = web.HTTPOk(
            headers={"X-Custom": "value"},
            reason="Done",
            text="text",
            content_type="custom",
        )
        assert resp.text == "text"
        compare: Mapping[str, str] = {"X-Custom": "value", "Content-Type": "custom"}
        assert resp.headers == compare
        assert resp.reason == "Done"
        assert resp.status == 200

    def test_pickle(self) -> None:
        resp = web.HTTPOk(
            headers={"X-Custom": "value"},
            reason="Done",
            text="text",
            content_type="custom",
        )
        resp.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Done"
            assert resp2.status == 200
            assert resp2.foo == "bar"

    async def test_app(self, aiohttp_client: AiohttpClient) -> None:
        async def handler(request: web.Request) -> NoReturn:
            raise web.HTTPOk()

        app = web.Application()
        app.router.add_get("/", handler)
        cli = await aiohttp_client(app)

        resp = await cli.get("/")
        assert 200 == resp.status
        txt = await resp.text()
        assert "200: OK" == txt


class TestHTTPFound:
    def test_location_str(self) -> None:
        exc = web.HTTPFound(location="/redirect")
        assert exc.location == URL("/redirect")
        assert exc.headers["Location"] == "/redirect"

    def test_location_url(self) -> None:
        exc = web.HTTPFound(location=URL("/redirect"))
        assert exc.location == URL("/redirect")
        assert exc.headers["Location"] == "/redirect"

    def test_empty_location(self) -> None:
        with pytest.raises(ValueError):
            web.HTTPFound(location="")
        with pytest.raises(ValueError):
            web.HTTPFound(location=None)  # type: ignore[arg-type]

    def test_location_CRLF(self) -> None:
        exc = web.HTTPFound(location="/redirect\r\n")
        assert "\r\n" not in exc.headers["Location"]

    def test_pickle(self) -> None:
        resp = web.HTTPFound(
            location="http://example.com",
            headers={"X-Custom": "value"},
            reason="Wow",
            text="text",
            content_type="custom",
        )
        resp.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.location == URL("http://example.com")
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Wow"
            assert resp2.status == 302
            assert resp2.foo == "bar"

    async def test_app(self, aiohttp_client: AiohttpClient) -> None:
        async def handler(request: web.Request) -> NoReturn:
            raise web.HTTPFound(location="/redirect")

        app = web.Application()
        app.router.add_get("/", handler)
        cli = await aiohttp_client(app)

        resp = await cli.get("/", allow_redirects=False)
        assert 302 == resp.status
        txt = await resp.text()
        assert "302: Found" == txt
        assert "/redirect" == resp.headers["location"]


class TestHTTPMethodNotAllowed:
    async def test_ctor(self) -> None:
        resp = web.HTTPMethodNotAllowed(
            "GET",
            ["POST", "PUT"],
            headers={"X-Custom": "value"},
            reason="Unsupported",
            text="text",
            content_type="custom",
        )
        assert resp.method == "GET"
        assert resp.allowed_methods == {"POST", "PUT"}
        assert resp.text == "text"
        compare: Mapping[str, str] = {
            "X-Custom": "value",
            "Content-Type": "custom",
            "Allow": "POST,PUT",
        }
        assert resp.headers == compare
        assert resp.reason == "Unsupported"
        assert resp.status == 405

    def test_pickle(self) -> None:
        resp = web.HTTPMethodNotAllowed(
            method="GET",
            allowed_methods=("POST", "PUT"),
            headers={"X-Custom": "value"},
            reason="Unsupported",
            text="text",
            content_type="custom",
        )
        resp.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.method == "GET"
            assert resp2.allowed_methods == {"POST", "PUT"}
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Unsupported"
            assert resp2.status == 405
            assert resp2.foo == "bar"


class TestHTTPRequestEntityTooLarge:
    def test_ctor(self) -> None:
        resp = web.HTTPRequestEntityTooLarge(
            max_size=100,
            actual_size=123,
            headers={"X-Custom": "value"},
            reason="Too large",
        )
        assert resp.text == (
            "Maximum request body size 100 exceeded, actual body size 123"
        )
        compare: Mapping[str, str] = {"X-Custom": "value", "Content-Type": "text/plain"}
        assert resp.headers == compare
        assert resp.reason == "Too large"
        assert resp.status == 413

    def test_pickle(self) -> None:
        resp = web.HTTPRequestEntityTooLarge(
            100, actual_size=123, headers={"X-Custom": "value"}, reason="Too large"
        )
        resp.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.text == resp.text
            assert resp2.headers == resp.headers
            assert resp2.reason == "Too large"
            assert resp2.status == 413
            assert resp2.foo == "bar"


class TestHTTPUnavailableForLegalReasons:
    def test_ctor(self) -> None:
        exc = web.HTTPUnavailableForLegalReasons(
            link="http://warning.or.kr/",
            headers={"X-Custom": "value"},
            reason="Zaprescheno",
            text="text",
            content_type="custom",
        )
        assert exc.link == URL("http://warning.or.kr/")
        assert exc.text == "text"
        compare: Mapping[str, str] = {
            "X-Custom": "value",
            "Content-Type": "custom",
            "Link": '<http://warning.or.kr/>; rel="blocked-by"',
        }
        assert exc.headers == compare
        assert exc.reason == "Zaprescheno"
        assert exc.status == 451

    def test_no_link(self) -> None:
        with pytest.raises(TypeError):
            web.HTTPUnavailableForLegalReasons()  # type: ignore[call-arg]

    def test_none_link(self) -> None:
        exc = web.HTTPUnavailableForLegalReasons(link=None)
        assert exc.link is None
        assert "Link" not in exc.headers

    def test_empty_link(self) -> None:
        exc = web.HTTPUnavailableForLegalReasons(link="")
        assert exc.link is None
        assert "Link" not in exc.headers

    def test_link_str(self) -> None:
        exc = web.HTTPUnavailableForLegalReasons(link="http://warning.or.kr/")
        assert exc.link == URL("http://warning.or.kr/")
        assert exc.headers["Link"] == '<http://warning.or.kr/>; rel="blocked-by"'

    def test_link_url(self) -> None:
        exc = web.HTTPUnavailableForLegalReasons(link=URL("http://warning.or.kr/"))
        assert exc.link == URL("http://warning.or.kr/")
        assert exc.headers["Link"] == '<http://warning.or.kr/>; rel="blocked-by"'

    def test_link_CRLF(self) -> None:
        exc = web.HTTPUnavailableForLegalReasons(link="http://warning.or.kr/\r\n")
        assert "\r\n" not in exc.headers["Link"]

    def test_pickle(self) -> None:
        resp = web.HTTPUnavailableForLegalReasons(
            link="http://warning.or.kr/",
            headers={"X-Custom": "value"},
            reason="Zaprescheno",
            text="text",
            content_type="custom",
        )
        resp.foo = "bar"  # type: ignore[attr-defined]
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.link == URL("http://warning.or.kr/")
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Zaprescheno"
            assert resp2.status == 451
            assert resp2.foo == "bar"
