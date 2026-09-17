"""Client support for Pyodide / Emscripten platforms (browsers, Node.js).

WebAssembly runtimes have no raw sockets, so the regular
:class:`~aiohttp.TCPConnector` cannot work there.  This module provides
:class:`FetchConnector`, a connector that dispatches each request through
the JavaScript ``fetch()`` API instead of a TCP connection.  It is picked
automatically by :class:`~aiohttp.ClientSession` when running under
Emscripten, so most code can simply use aiohttp as usual.

The connector speaks regular HTTP/1.1 with the rest of the client stack:
the serialized request is decoded with :class:`~aiohttp.http.HttpRequestParser`
and the ``fetch()`` result is re-serialized into HTTP/1.1 response bytes fed
through the standard :class:`~aiohttp.client_proto.ResponseHandler`.  This
keeps ``ClientSession`` itself completely unaware of the platform.

Limitations imposed by ``fetch()``:

* No proxies, no ``CONNECT``, no connection upgrades (WebSockets).
* Redirects are followed transparently by the browser; aiohttp only sees
  the final response and cannot report redirect history.
* The trust store, cookies (in browsers) and CORS policy are managed by the
  JavaScript runtime, not by aiohttp; ``ssl`` arguments are ignored.
* ``Expect: 100-continue`` is answered locally instead of by the server.
"""

import asyncio
import sys
from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Any, Final

from . import hdrs
from .base_protocol import BaseProtocol
from .client_exceptions import ClientConnectionError
from .client_proto import ResponseHandler
from .connector import BaseConnector
from .helpers import EMPTY_BODY_STATUS_CODES, set_exception, set_result
from .http import HttpRequestParser
from .http_parser import RawRequestMessage
from .streams import StreamReader

if TYPE_CHECKING:
    from .client import ClientTimeout
    from .client_reqrep import ClientRequest
    from .tracing import Trace

__all__ = ("FetchConnector",)

IS_EMSCRIPTEN: Final = sys.platform == "emscripten"

# Connection management and body framing are handled by fetch() itself
# (browsers forbid many of these outright), and the body handed to fetch()
# is already unframed and decoded, so these request headers must not be
# forwarded.
_UNSENDABLE_REQUEST_HEADERS: Final = frozenset(
    (
        hdrs.ACCEPT_ENCODING.lower(),
        hdrs.CONNECTION.lower(),
        hdrs.CONTENT_ENCODING.lower(),
        hdrs.CONTENT_LENGTH.lower(),
        hdrs.EXPECT.lower(),
        hdrs.HOST.lower(),
        hdrs.KEEP_ALIVE.lower(),
        hdrs.PROXY_AUTHENTICATE.lower(),
        hdrs.PROXY_AUTHORIZATION.lower(),
        hdrs.TE.lower(),
        hdrs.TRAILER.lower(),
        hdrs.TRANSFER_ENCODING.lower(),
        hdrs.UPGRADE.lower(),
    )
)

# fetch() exposes the response body already decompressed and unframed, so
# the original framing headers would contradict the bytes we feed to the
# response parser.  Set-Cookie is skipped here because the iterator folds
# repeated values into one comma-joined string; it is recovered separately
# via Headers.getSetCookie() where available.
_UNUSABLE_RESPONSE_HEADERS: Final = frozenset(
    (
        hdrs.CONNECTION.lower(),
        hdrs.CONTENT_ENCODING.lower(),
        hdrs.CONTENT_LENGTH.lower(),
        hdrs.KEEP_ALIVE.lower(),
        hdrs.SET_COOKIE.lower(),
        hdrs.TRANSFER_ENCODING.lower(),
    )
)


class _RequestSinkProtocol(BaseProtocol):
    """Owner protocol for the request parser; flow control is a no-op."""

    def pause_reading(self) -> None:
        self._reading_paused = True

    def resume_reading(self, resume_parser: bool = True) -> None:
        self._reading_paused = False


class _FetchTransport(asyncio.Transport):
    """Fake transport that hands written request bytes back to the protocol."""

    def __init__(self, protocol: "FetchClientProtocol") -> None:
        super().__init__()
        self._protocol = protocol
        self._closing = False

    def write(self, data: "bytes | bytearray | memoryview[Any]") -> None:
        self._protocol._request_bytes_received(bytes(data))

    def writelines(
        self, list_of_data: "Iterable[bytes | bytearray | memoryview[Any]]"
    ) -> None:
        self.write(b"".join(bytes(data) for data in list_of_data))

    def is_closing(self) -> bool:
        return self._closing

    def close(self) -> None:
        if not self._closing:
            self._closing = True
            self._protocol._transport_closed()

    def abort(self) -> None:
        self.close()


class FetchClientProtocol(ResponseHandler):
    """A ResponseHandler that round-trips one request through ``fetch()``.

    The request bytes written by ``ClientRequest`` are decoded with
    ``HttpRequestParser``; once the request body is complete it is sent with
    ``fetch()`` and the JavaScript response is re-serialized into HTTP/1.1
    bytes for the regular response parser.  Each protocol instance serves
    exactly one request (``FetchConnector`` never pools connections).
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        request: "ClientRequest",
        *,
        fetch: Callable[..., Any],
        fetch_options: Mapping[str, Any],
    ) -> None:
        super().__init__(loop)
        self._request = request
        self._js_fetch = fetch
        self._fetch_options = fetch_options
        self._fetch_task: asyncio.Task[None] | None = None
        self._abort_controller: Any = None
        sink = _RequestSinkProtocol(loop)
        self._request_parser = HttpRequestParser(sink, loop, 2**16)
        self.connection_made(_FetchTransport(self))

    def _request_bytes_received(self, data: bytes) -> None:
        messages, _, _ = self._request_parser.feed_data(data)
        if messages and self._fetch_task is None:
            message, payload = messages[0]
            self._fetch_task = self._loop.create_task(
                self._fetch_and_respond(message, payload)
            )

    def _transport_closed(self) -> None:
        if self._abort_controller is not None:
            self._abort_controller.abort()
            self._abort_controller = None
        if self._fetch_task is not None and not self._fetch_task.done():
            self._fetch_task.cancel()
        if not self._connection_lost_called:
            self._loop.call_soon(self.connection_lost, None)

    def _make_fetch_arguments(
        self, message: RawRequestMessage, body: bytes
    ) -> dict[str, Any]:
        headers = [
            (name, value)
            for name, value in message.headers.items()
            if name.lower() not in _UNSENDABLE_REQUEST_HEADERS
        ]
        options: dict[str, Any] = {"method": message.method, "headers": headers}
        if body:
            options["body"] = body
        options.update(self._fetch_options)
        if IS_EMSCRIPTEN:  # pragma: no cover
            from js import AbortController  # noqa: I900
            from pyodide.ffi import to_js  # noqa: I900

            self._abort_controller = AbortController.new()
            options["signal"] = self._abort_controller.signal
            # An array of [name, value] arrays is a valid HeadersInit.
            options["headers"] = to_js(options["headers"])
            if body:
                options["body"] = to_js(body)
        return options

    async def _fetch_and_respond(
        self, message: RawRequestMessage, payload: StreamReader
    ) -> None:
        try:
            body = await payload.read()
            options = self._make_fetch_arguments(message, body)
            jsresp = await self._js_fetch(str(self._request.url), **options)
            self.data_received(await self._serialize_response(message, jsresp))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            set_exception(
                self,
                ClientConnectionError(f"fetch() failed: {exc!r}"),
                exc,
            )

    async def _serialize_response(
        self, message: RawRequestMessage, jsresp: Any
    ) -> bytes:
        body: bytes = (await jsresp.arrayBuffer()).to_bytes()
        status = jsresp.status
        lines = [f"HTTP/1.1 {status} {jsresp.statusText}".rstrip()]
        lines.extend(
            f"{name}: {value}"
            for name, value in jsresp.headers
            if name.lower() not in _UNUSABLE_RESPONSE_HEADERS
        )
        if hasattr(jsresp.headers, "getSetCookie"):
            lines.extend(f"Set-Cookie: {c}" for c in jsresp.headers.getSetCookie())
        if status not in EMPTY_BODY_STATUS_CODES and message.method != hdrs.METH_HEAD:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        head = "\r\n".join(lines).encode("latin-1", "backslashreplace")
        return head + b"\r\n\r\n" + body


class FetchConnector(BaseConnector):
    """Connector that performs requests via the JavaScript ``fetch()`` API.

    Used as the default connector when running under Emscripten (Pyodide).

    fetch - The fetch implementation to use.  Defaults to ``js.fetch``;
        mainly useful for testing or wrapping fetch with custom behavior.
    fetch_options - Extra options merged into the ``fetch()`` init argument,
        e.g. ``{"credentials": "include", "cache": "no-store"}``.
    limit - The total number of simultaneous in-flight requests.
    limit_per_host - Number of simultaneous requests to one host.
    """

    def __init__(
        self,
        *,
        fetch: Callable[..., Any] | None = None,
        fetch_options: Mapping[str, Any] | None = None,
        limit: int = 100,
        limit_per_host: int = 0,
    ) -> None:
        if fetch is None:
            if not IS_EMSCRIPTEN:
                raise RuntimeError(
                    "FetchConnector requires the JavaScript fetch() API and only "
                    "works under Emscripten/Pyodide (or with an explicit fetch=)"
                )
            from js import fetch as js_fetch  # noqa: I900  # pragma: no cover

            fetch = js_fetch  # pragma: no cover
        super().__init__(force_close=True, limit=limit, limit_per_host=limit_per_host)
        self._fetch = fetch
        self._fetch_options = dict(fetch_options or {})

    async def _create_connection(
        self, req: "ClientRequest", traces: list["Trace"], timeout: "ClientTimeout"
    ) -> ResponseHandler:
        if req.proxy is not None:
            raise ClientConnectionError(
                "Proxies are not supported by fetch(); "
                "the JavaScript runtime manages the network path"
            )
        if req.method == hdrs.METH_CONNECT or hdrs.UPGRADE in req.headers:
            raise ClientConnectionError(
                "Connection upgrades (e.g. WebSockets) are not supported by "
                "fetch(); use the JavaScript WebSocket API instead"
            )
        if req._continue is not None:
            # There is no way to wait for a real 100 Continue over fetch().
            set_result(req._continue, True)
        return FetchClientProtocol(
            self._loop, req, fetch=self._fetch, fetch_options=self._fetch_options
        )
