import asyncio
import json
from typing import Any, AsyncIterator, Awaitable, Callable, Optional
from contextlib import asynccontextmanager

from .typedefs import JSONEncoder
from .web_response import StreamResponse
from . import hdrs

__all__ = ("EventSourceResponse", "sse_response", "sse")


class EventSourceResponse(StreamResponse):
    """
    Server-Sent Events (SSE) response.

    - Content-Type: text/event-stream
    - Cache-Control: no-cache
    - Connection: keep-alive

    Supports:
    - send(data, event=None, id=None, retry=None, topic=None, json=False, encoder=None)
    - comment(text)
    - Optional backpressure queue with strategies: "block" | "drop_old" | "drop_new"
    - Optional compression: brotli ("br") or zstd ("zstd") if libraries are available
    """

    def __init__(
        self,
        *,
        headers: Optional[dict[str, str]] = None,
        queue_size: int | None = None,
        backpressure: str = "block",
        compress: str | None = None,
        encoder: JSONEncoder | None = None,
    ) -> None:
        real_headers: dict[str, str] = {
            hdrs.CONTENT_TYPE: "text/event-stream; charset=utf-8",
            hdrs.CACHE_CONTROL: "no-cache",
            hdrs.CONNECTION: "keep-alive",
        }
        if headers:
            # allow user-provided headers to override defaults if desired
            real_headers.update(headers)

        super().__init__(status=200, headers=real_headers)

        # SSE streams are chunked, keep the connection alive
        self._chunked = True
        self._compression = False  # use custom compression handling if requested

        # Optional JSON encoder
        self._json_encoder: JSONEncoder | None = encoder

        # Queue/backpressure
        self._queue: asyncio.Queue[bytes] | None = None
        self._queue_task: asyncio.Task[None] | None = None
        self._backpressure = backpressure
        if queue_size is not None and queue_size > 0:
            self._queue = asyncio.Queue(maxsize=queue_size)

        # Heartbeat task
        self._heartbeat_task: asyncio.Task[None] | None = None

        # Compression (manual streaming compressor if available)
        self._compress: str | None = None
        self._compressor: Any | None = None
        if compress in ("br", "zstd"):
            self._setup_compression(compress)

        # Closed flag to stop background tasks
        self._closed = False

    # -----------------------
    # Public API
    # -----------------------
    async def send(
        self,
        data: Any,
        *,
        event: str | None = None,
        id: str | int | None = None,
        retry: int | None = None,
        topic: str | None = None,
        json: bool = False,
        encoder: JSONEncoder | None = None,
    ) -> None:
        """Send an SSE event.

        data may be a string or an object. If json=True, serialize using
        json.dumps or a provided encoder.
        """
        payload = self._format_event(
            data=data,
            event=event,
            id=id,
            retry=retry,
            topic=topic,
            json=json,
            encoder=encoder,
        )
        await self._deliver(payload)

    async def comment(self, text: str) -> None:
        """Send an SSE comment line."""
        # Comments start with ':' and end with a blank line separator
        payload = f":{text}\n\n".encode("utf-8")
        await self._deliver(payload)

    # -----------------------
    # Internal helpers
    # -----------------------
    def _setup_compression(self, compress: str) -> None:
        self._compress = None
        self._compressor = None
        if compress == "br":
            try:
                import brotli  # type: ignore

                # brotli module provides a Compressor with a .compress() method
                self._compressor = brotli.Compressor()
                self._compress = "br"
                # Advertise content-encoding only if compressor is available
                self._headers[hdrs.CONTENT_ENCODING] = "br"
            except Exception:
                # Brotli not available or no streaming support; silently skip
                pass
        elif compress == "zstd":
            try:
                import zstandard as zstd  # type: ignore

                self._compressor = zstd.ZstdCompressor().compressobj()
                self._compress = "zstd"
                self._headers[hdrs.CONTENT_ENCODING] = "zstd"
            except Exception:
                pass

    def _encode_chunk(self, chunk: bytes) -> bytes:
        if not self._compressor:
            return chunk
        try:
            # Try to stream compress; for zstd add a block flush to make data visible
            out = self._compressor.compress(chunk)
            # Optional flush for streaming visibility
            try:
                import zstandard as zstd  # type: ignore

                if hasattr(self._compressor, "flush"):
                    out += self._compressor.flush(zstd.FLUSH_BLOCK)
            except Exception:
                # brotli.Compressor.flush() returns an empty bytes until final flush; skip
                pass
            return out
        except Exception:
            # If compression fails unexpectedly, fall back to raw
            return chunk

    def _format_event(
        self,
        *,
        data: Any,
        event: str | None,
        id: str | int | None,
        retry: int | None,
        topic: str | None,
        json: bool,
        encoder: JSONEncoder | None,
    ) -> bytes:
        lines: list[str] = []

        if event is not None:
            lines.append(f"event: {event}")
        if id is not None:
            lines.append(f"id: {id}")
        if retry is not None:
            lines.append(f"retry: {retry}")
        if topic is not None:
            # non-standard, useful for server-side topic filtering
            lines.append(f"topic: {topic}")

        # data field supports multi-line; each line prefixed with 'data: '
        if isinstance(data, str) and not json:
            payload_str = data
        else:
            dumps = encoder or self._json_encoder or json_module.dumps
            payload_str = dumps(data)
        for part in payload_str.splitlines() or [""]:
            lines.append(f"data: {part}")

        # Event terminator blank line
        formatted = "\n".join(lines) + "\n\n"
        return formatted.encode("utf-8")

    async def _deliver(self, payload: bytes) -> None:
        if self._closed:
            return
        data = self._encode_chunk(payload)
        if self._queue is None:
            await self._write_now(data)
        else:
            await self._enqueue(data)

    async def _write_now(self, data: bytes) -> None:
        try:
            await self.write(data)
        except (ConnectionError, asyncio.CancelledError):
            await self._handle_disconnect()
        except Exception:
            # Any write failure should stop the stream
            await self._handle_disconnect()

    async def _enqueue(self, data: bytes) -> None:
        assert self._queue is not None
        strategy = self._backpressure
        if strategy == "block":
            await self._queue.put(data)
        elif strategy == "drop_old":
            if self._queue.full():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    pass
            await self._queue.put(data)
        elif strategy == "drop_new":
            if not self._queue.full():
                await self._queue.put(data)
        else:
            # Unknown strategy -> default to block
            await self._queue.put(data)

    async def _queue_consumer(self) -> None:
        assert self._queue is not None
        try:
            while not self._closed:
                data = await self._queue.get()
                try:
                    await self.write(data)
                except (ConnectionError, asyncio.CancelledError):
                    await self._handle_disconnect()
                    return
                except Exception:
                    await self._handle_disconnect()
                    return
                finally:
                    self._queue.task_done()
        finally:
            # Drain remaining items silently
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break

    def start_queue(self) -> None:
        if self._queue is not None and self._queue_task is None:
            loop = asyncio.get_running_loop()
            self._queue_task = loop.create_task(self._queue_consumer())

    def start_heartbeat(self, interval: float, comment_text: str = "heartbeat") -> None:
        if self._heartbeat_task is not None:
            return
        loop = asyncio.get_running_loop()
        async def _beat() -> None:
            try:
                while not self._closed:
                    await asyncio.sleep(interval)
                    # Either ':heartbeat:' or a comment("keep-alive")
                    await self.comment(comment_text)
            except asyncio.CancelledError:
                pass
        self._heartbeat_task = loop.create_task(_beat())

    async def _handle_disconnect(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Stop heartbeat and queue consumer
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
        if self._queue_task is not None:
            self._queue_task.cancel()
            self._queue_task = None
        # Try to close the payload writer
        with suppress_exceptions(asyncio.CancelledError, ConnectionError):
            await self.write_eof()


@asynccontextmanager
async def sse_response(
    request: "Any",
    *,
    heartbeat: float | None = 15,
    json: bool = False,
    encoder: JSONEncoder | None = None,
    compress: str | None = None,
    queue_size: int | None = None,
    backpressure: str = "block",
) -> AsyncIterator[EventSourceResponse]:
    """Async context manager to prepare and manage an SSE response lifecycle.

    - Prepares headers
    - Starts heartbeat (':heartbeat:' or comment("keep-alive"))
    - Cancels heartbeat and closes connection on exit
    - Optional compression with 'br' or 'zstd' if available
    """
    resp = EventSourceResponse(
        headers=None,
        queue_size=queue_size,
        backpressure=backpressure,
        compress=compress,
        encoder=encoder,
    )
    await resp.prepare(request)
    # Start queue consumer if configured
    resp.start_queue()
    # Heartbeat
    if heartbeat and heartbeat > 0:
        # Choose a simple comment text to keep proxies awake
        resp.start_heartbeat(heartbeat, comment_text="keep-alive")
    try:
        yield resp
    finally:
        # Stop heartbeat/queue and close
        await resp._handle_disconnect()


def sse(handler: Optional[Callable[..., Awaitable[Any]]] = None, **opts: Any):
    """Decorator to turn a request handler into an SSE endpoint.

    Usage:
        @sse(heartbeat=15)
        async def handler(request, resp):
            await resp.send({...})

    The wrapped handler will receive an extra positional argument: the
    EventSourceResponse instance, and runs inside sse_response context.
    """

    def _decorate(fn: Callable[..., Awaitable[Any]]):
        async def _wrapped(request: Any) -> EventSourceResponse:
            async with sse_response(request, **opts) as resp:
                try:
                    # Call user function with (request, resp)
                    await fn(request, resp)
                except asyncio.CancelledError:
                    # client disconnected
                    pass
                except Exception:
                    # Abort on unhandled exceptions; ensure stream closes
                    await resp._handle_disconnect()
                # Return the response for aiohttp
                return resp
        return _wrapped

    return _decorate(handler) if handler is not None else _decorate


# Local simple JSON module indirection to allow injection
class _JSONModule:
    def dumps(self, obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False)


json_module = _JSONModule()


class suppress_exceptions:
    def __init__(self, *exc_types: type[BaseException]):
        self.exc_types = exc_types

    async def __aenter__(self):  # type: ignore[override]
        return None

    async def __aexit__(self, exc_type, exc, tb):  # type: ignore[override]
        return exc is not None and any(isinstance(exc, t) for t in self.exc_types)

