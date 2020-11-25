# type: ignore
import collections
import pickle
from traceback import format_exception
from typing import Any

import pytest
from yarl import URL

from aiohttp import web


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
    assert resp.headers == {"Content-Type": "text/plain"}
    assert resp.reason == "OK"
    assert resp.status == 200
    assert bool(resp)


async def test_ctor_with_headers() -> None:
    resp = web.HTTPOk(headers={"X-Custom": "value"})
    assert resp.text == "200: OK"
    assert resp.headers == {"Content-Type": "text/plain", "X-Custom": "value"}
    assert resp.reason == "OK"
    assert resp.status == 200


async def test_ctor_content_type() -> None:
    resp = web.HTTPOk(text="text", content_type="custom")
    assert resp.text == "text"
    assert resp.headers == {"Content-Type": "custom"}
    assert resp.reason == "OK"
    assert resp.status == 200
    assert bool(resp)


async def test_ctor_content_type_without_text() -> None:
    with pytest.warns(DeprecationWarning):
        resp = web.HTTPResetContent(content_type="custom")
    assert resp.text is None
    assert resp.headers == {"Content-Type": "custom"}
    assert resp.reason == "Reset Content"
    assert resp.status == 205
    assert bool(resp)


async def test_ctor_text_for_empty_body() -> None:
    with pytest.warns(DeprecationWarning):
        resp = web.HTTPResetContent(text="text")
    assert resp.text == "text"
    assert resp.headers == {"Content-Type": "text/plain"}
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
        assert resp.headers == {"X-Custom": "value", "Content-Type": "custom"}
        assert resp.reason == "Done"
        assert resp.status == 200

    def test_pickle(self) -> None:
        resp = web.HTTPOk(
            headers={"X-Custom": "value"},
            reason="Done",
            text="text",
            content_type="custom",
        )
        resp.foo = "bar"
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Done"
            assert resp2.status == 200
            assert resp2.foo == "bar"

    async def test_app(self, aiohttp_client: Any) -> None:
        async def handler(request):
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
            web.HTTPFound(location=None)

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
        resp.foo = "bar"
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.location == URL("http://example.com")
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Wow"
            assert resp2.status == 302
            assert resp2.foo == "bar"

    async def test_app(self, aiohttp_client: Any) -> None:
        async def handler(request):
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
        assert resp.headers == {
            "X-Custom": "value",
            "Content-Type": "custom",
            "Allow": "POST,PUT",
        }
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
        resp.foo = "bar"
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
            "Maximum request body size 100 exceeded, " "actual body size 123"
        )
        assert resp.headers == {"X-Custom": "value", "Content-Type": "text/plain"}
        assert resp.reason == "Too large"
        assert resp.status == 413

    def test_pickle(self) -> None:
        resp = web.HTTPRequestEntityTooLarge(
            100, actual_size=123, headers={"X-Custom": "value"}, reason="Too large"
        )
        resp.foo = "bar"
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
        resp = web.HTTPUnavailableForLegalReasons(
            link="http://warning.or.kr/",
            headers={"X-Custom": "value"},
            reason="Zaprescheno",
            text="text",
            content_type="custom",
        )
        assert resp.link == URL("http://warning.or.kr/")
        assert resp.text == "text"
        assert resp.headers == {
            "X-Custom": "value",
            "Content-Type": "custom",
            "Link": '<http://warning.or.kr/>; rel="blocked-by"',
        }
        assert resp.reason == "Zaprescheno"
        assert resp.status == 451

    def test_pickle(self) -> None:
        resp = web.HTTPUnavailableForLegalReasons(
            link="http://warning.or.kr/",
            headers={"X-Custom": "value"},
            reason="Zaprescheno",
            text="text",
            content_type="custom",
        )
        resp.foo = "bar"
        for proto in range(2, pickle.HIGHEST_PROTOCOL + 1):
            pickled = pickle.dumps(resp, proto)
            resp2 = pickle.loads(pickled)
            assert resp2.link == URL("http://warning.or.kr/")
            assert resp2.text == "text"
            assert resp2.headers == resp.headers
            assert resp2.reason == "Zaprescheno"
            assert resp2.status == 451
            assert resp2.foo == "bar"
