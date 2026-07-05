"""Tests for aiohttp.pyodide.FetchConnector using a stubbed fetch().

These tests exercise the whole fetch-based client pipeline (request
serialization, request parsing, response synthesis) without requiring an
Emscripten runtime: the JavaScript ``fetch()`` entry point is replaced with
an in-process stub.  Integration tests running under a real Pyodide runtime
live in ``tests/test_pyodide.py``.
"""

import asyncio
import json
import sys
from typing import Any, NoReturn, Union
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp.pyodide import FetchClientProtocol, FetchConnector, _FetchTransport


class StubArrayBuffer:
    """Mimics a JsProxy of an ArrayBuffer."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def to_bytes(self) -> bytes:
        return self._data


class StubHeaders(list[tuple[str, str]]):
    """Mimics iteration over a JavaScript Headers object."""

    def __init__(
        self,
        entries: list[tuple[str, str]],
        set_cookies: tuple[str, ...] = (),
    ) -> None:
        super().__init__(entries)
        self._set_cookies = list(set_cookies)

    def getSetCookie(self) -> list[str]:
        return self._set_cookies


class StubJsResponse:
    """Mimics a JsProxy of a fetch() Response."""

    def __init__(
        self,
        status: int = 200,
        statusText: str = "OK",
        headers: Union[StubHeaders, None] = None,
        body: bytes = b"",
    ) -> None:
        self.status = status
        self.statusText = statusText
        self.headers = headers if headers is not None else StubHeaders([])
        self._body = body

    async def arrayBuffer(self) -> StubArrayBuffer:
        return StubArrayBuffer(self._body)


class StubFetch:
    """Records calls and replies with a canned response."""

    def __init__(self, response: Union[StubJsResponse, None] = None) -> None:
        self.response = response if response is not None else StubJsResponse()
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, url: str, **options: Any) -> StubJsResponse:
        self.calls.append((url, options))
        return self.response

    @property
    def last_options(self) -> dict[str, Any]:
        return self.calls[-1][1]

    @property
    def last_headers(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.last_options["headers"]}


async def test_get_request() -> None:
    fetch = StubFetch(
        StubJsResponse(
            headers=StubHeaders([("content-type", "text/html; charset=utf-8")]),
            body=b"<h1>hi</h1>",
        )
    )
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.get("http://example.com/page?q=1") as resp:
            assert resp.status == 200
            assert resp.reason == "OK"
            assert resp.headers["Content-Type"] == "text/html; charset=utf-8"
            assert await resp.text() == "<h1>hi</h1>"

    url, options = fetch.calls[0]
    assert url == "http://example.com/page?q=1"
    assert options["method"] == "GET"
    assert "body" not in options


async def test_request_headers_forwarded_and_filtered() -> None:
    fetch = StubFetch()
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        await session.get("http://example.com/", headers={"X-Custom": "yes"})

    headers = fetch.last_headers
    assert headers["x-custom"] == "yes"
    assert "aiohttp" in headers["user-agent"]
    # fetch() manages connection lifetime, framing and content negotiation.
    for forbidden in ("host", "connection", "content-length", "accept-encoding"):
        assert forbidden not in headers


async def test_post_bytes_body() -> None:
    fetch = StubFetch()
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        await session.post("http://example.com/", data=b"some-bytes")

    assert bytes(fetch.last_options["body"]) == b"some-bytes"
    assert fetch.last_options["method"] == "POST"


async def test_post_json_body() -> None:
    fetch = StubFetch()
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        await session.post("http://example.com/", json={"x": 1})

    assert json.loads(bytes(fetch.last_options["body"])) == {"x": 1}
    assert fetch.last_headers["content-type"] == "application/json"


async def test_chunked_body_is_unframed() -> None:
    """A chunked request body must be de-chunked before it reaches fetch()."""

    async def gen() -> Any:
        yield b"chunk1-"
        yield b"chunk2"

    fetch = StubFetch()
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        await session.post("http://example.com/", data=gen())

    assert bytes(fetch.last_options["body"]) == b"chunk1-chunk2"
    assert "transfer-encoding" not in fetch.last_headers


async def test_response_framing_headers_stripped() -> None:
    """fetch() bodies arrive decoded; stale framing headers must not leak."""
    fetch = StubFetch(
        StubJsResponse(
            headers=StubHeaders(
                [
                    ("content-type", "text/plain"),
                    # Values describe the on-the-wire (compressed) form and
                    # would contradict the decoded body fetch() hands over.
                    ("content-encoding", "gzip"),
                    ("content-length", "999999"),
                ]
            ),
            body=b"decoded",
        )
    )
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.get("http://example.com/") as resp:
            assert await resp.read() == b"decoded"
            assert "Content-Encoding" not in resp.headers
            assert resp.headers["Content-Length"] == "7"


async def test_set_cookie_headers_recovered() -> None:
    """Repeated Set-Cookie headers come from getSetCookie(), not iteration."""
    fetch = StubFetch(
        StubJsResponse(
            headers=StubHeaders(
                [("set-cookie", "a=1; Path=/, b=2; Path=/")],
                set_cookies=("a=1; Path=/", "b=2; Path=/"),
            ),
            body=b"ok",
        )
    )
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.get("http://example.com/") as resp:
            assert list(resp.headers.getall("Set-Cookie")) == [
                "a=1; Path=/",
                "b=2; Path=/",
            ]
        cookies = session.cookie_jar.filter_cookies(resp.url)
        assert cookies["a"].value == "1"
        assert cookies["b"].value == "2"


async def test_no_content_response() -> None:
    fetch = StubFetch(StubJsResponse(status=204, statusText="No Content"))
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.get("http://example.com/") as resp:
            assert resp.status == 204
            assert await resp.read() == b""


async def test_head_request() -> None:
    fetch = StubFetch(
        StubJsResponse(headers=StubHeaders([("content-type", "text/plain")]))
    )
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.head("http://example.com/") as resp:
            assert resp.status == 200
            assert await resp.read() == b""
    assert fetch.last_options["method"] == "HEAD"


async def test_fetch_failure_raises_client_error() -> None:
    async def failing_fetch(url: str, **options: Any) -> NoReturn:
        raise TypeError("Failed to fetch")

    async with aiohttp.ClientSession(
        connector=FetchConnector(fetch=failing_fetch)
    ) as session:
        with pytest.raises(aiohttp.ClientConnectionError, match="Failed to fetch"):
            await session.get("http://example.com/")


async def test_proxy_rejected() -> None:
    async with aiohttp.ClientSession(
        connector=FetchConnector(fetch=StubFetch())
    ) as session:
        with pytest.raises(aiohttp.ClientConnectionError, match="[Pp]roxies"):
            await session.get("http://example.com/", proxy="http://proxy.example:8080")


async def test_websocket_rejected() -> None:
    async with aiohttp.ClientSession(
        connector=FetchConnector(fetch=StubFetch())
    ) as session:
        with pytest.raises(aiohttp.ClientConnectionError, match="WebSocket"):
            await session.ws_connect("http://example.com/ws")


async def test_expect100_answered_locally() -> None:
    fetch = StubFetch()
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.post(
            "http://example.com/", data=b"abc", expect100=True
        ) as resp:
            assert resp.status == 200

    assert bytes(fetch.last_options["body"]) == b"abc"


async def test_fetch_options_merged() -> None:
    fetch = StubFetch()
    connector = FetchConnector(fetch=fetch, fetch_options={"credentials": "include"})
    async with aiohttp.ClientSession(connector=connector) as session:
        await session.get("http://example.com/")

    assert fetch.last_options["credentials"] == "include"


async def test_total_timeout_cancels_fetch() -> None:
    cancelled = asyncio.Event()

    async def hanging_fetch(url: str, **options: Any) -> NoReturn:
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async with aiohttp.ClientSession(
        connector=FetchConnector(fetch=hanging_fetch),
        timeout=aiohttp.ClientTimeout(total=0.05),
    ) as session:
        with pytest.raises(asyncio.TimeoutError):
            await session.get("http://example.com/")
        await asyncio.wait_for(cancelled.wait(), 1)


async def test_concurrent_requests() -> None:
    fetch = StubFetch(StubJsResponse(body=b"payload"))
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        responses = await asyncio.gather(
            *(session.get("http://example.com/") for _ in range(10))
        )
        for resp in responses:
            assert await resp.read() == b"payload"
            resp.release()

    assert len(fetch.calls) == 10


async def test_large_body_pauses_request_stream() -> None:
    """A body larger than the request parser's buffer exercises flow control."""
    big = b"x" * 200_000
    fetch = StubFetch()
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        await session.post("http://example.com/", data=big)

    assert bytes(fetch.last_options["body"]) == big


async def test_response_headers_without_get_set_cookie() -> None:
    """Runtimes without Headers.getSetCookie() still work (without cookies)."""
    fetch = StubFetch(
        StubJsResponse(headers=[("content-type", "text/plain")], body=b"ok")  # type: ignore[arg-type]
    )
    async with aiohttp.ClientSession(connector=FetchConnector(fetch=fetch)) as session:
        async with session.get("http://example.com/") as resp:
            assert await resp.read() == b"ok"


async def test_transport_close_aborts_fetch() -> None:
    """Closing the connection aborts the in-flight fetch()."""
    request = mock.Mock()
    request.url = URL("http://example.com/")
    protocol = FetchClientProtocol(
        asyncio.get_running_loop(), request, fetch=StubFetch(), fetch_options={}
    )
    controller = mock.Mock()
    protocol._abort_controller = controller
    protocol._fetch_task = asyncio.ensure_future(asyncio.sleep(3600))
    transport = protocol.transport
    assert transport is not None
    assert not transport.is_closing()
    transport.abort()
    transport.close()  # Second close is a no-op.
    assert transport.is_closing()
    assert controller.abort.called
    await asyncio.sleep(0)
    assert protocol._fetch_task.cancelled()


def test_transport_writelines() -> None:
    written: list[bytes] = []
    protocol = mock.Mock()
    protocol._request_bytes_received = written.append
    transport = _FetchTransport(protocol)
    transport.writelines([b"a", bytearray(b"b"), memoryview(b"c")])
    assert written == [b"abc"]


@pytest.mark.skipif(sys.platform == "emscripten", reason="fetch() exists here")
def test_requires_fetch_outside_emscripten() -> None:
    with pytest.raises(RuntimeError, match="Emscripten"):
        FetchConnector()


@pytest.mark.skipif(sys.platform == "emscripten", reason="patches the platform")
async def test_default_connector_selected_by_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under Emscripten, ClientSession defaults to FetchConnector.

    Off-platform the constructor raises because the fetch() API is missing,
    which is enough to prove the selection logic without a WebAssembly
    runtime; real construction is covered in tests/test_pyodide.py.
    """
    monkeypatch.setattr(sys, "platform", "emscripten")
    with pytest.raises(RuntimeError, match="Emscripten"):
        aiohttp.ClientSession()
