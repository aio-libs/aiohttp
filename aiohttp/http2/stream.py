import asyncio
import logging
from enum import IntEnum
from typing import TYPE_CHECKING, Dict, Iterable, Optional, Set

from hpack import HeaderTuple

from ..http_exceptions import ContentEncodingError
from ..http_parser import DeflateBuffer, RawResponseMessage
from ..streams import StreamReader
from .adapter import feed_headers
from .errors import ErrorCode, ProtocolError
from .settings import Setting

if TYPE_CHECKING:
    from .connection import Http2Connection, Http2Protocol

logger = logging.getLogger("aiohttp.http2.stream")

# Limit for decompressed frames
# the hard limit is  2**63 -1 but
# setting it to a reasonable value
# protects the client against zip bombs
# and similar attacks.
# Zip bombs are a (rather unorthodox)
# defense tactic against scrapers
# so it's important to protect
# the client against them.
MAX_DECOMPRESS_SIZE = 2**31 - 1


# ----------------------------------------------------------------------
# Stream State Machine (RFC 7540 5.1)
# ----------------------------------------------------------------------
class StreamState(IntEnum):
    IDLE = 0
    RESERVED_LOCAL = 1
    RESERVED_REMOTE = 2
    OPEN = 3
    HALF_CLOSED_LOCAL = 4
    HALF_CLOSED_REMOTE = 5
    CLOSED = 6


# Valid transitions (RFC 7540 Figure 2)
VALID_TRANSITIONS: Dict[StreamState, Set[StreamState]] = {
    StreamState.IDLE: {
        StreamState.OPEN,
        StreamState.RESERVED_LOCAL,
        StreamState.RESERVED_REMOTE,
    },
    StreamState.RESERVED_LOCAL: {StreamState.HALF_CLOSED_REMOTE, StreamState.CLOSED},
    StreamState.RESERVED_REMOTE: {StreamState.HALF_CLOSED_LOCAL, StreamState.CLOSED},
    StreamState.OPEN: {StreamState.HALF_CLOSED_LOCAL, StreamState.HALF_CLOSED_REMOTE},
    StreamState.HALF_CLOSED_LOCAL: {StreamState.CLOSED},
    StreamState.HALF_CLOSED_REMOTE: {StreamState.CLOSED},
    StreamState.CLOSED: set(),
}


class Stream:
    """A single HTTP/2 stream with streaming support and optional decompression."""

    __slots__ = (
        "stream_id",
        "state",
        "conn",
        "outbound_window",
        "inbound_window",
        "response_future",
        "response_headers",
        "response",
        "body_reader",
        "decompressor",
        "_pending_data",
        "_headers_received",
        "_inbound_window_initial",
        "_auto_decompress",
        "closed_event",
    )

    def __init__(
        self,
        stream_id: int,
        conn: "Http2Connection",
        loop: asyncio.AbstractEventLoop,
        protocol: "Http2Protocol",
    ) -> None:
        self.stream_id = stream_id
        self.state = StreamState.IDLE
        self.conn = conn

        # Flow-control windows
        self.outbound_window: int = conn.remote_settings[Setting.INITIAL_WINDOW_SIZE]
        self.inbound_window: int = conn.local_settings[Setting.INITIAL_WINDOW_SIZE]
        self._inbound_window_initial: int = self.inbound_window

        self.response_future: asyncio.Future[
            tuple[RawResponseMessage, StreamReader]
        ] = loop.create_future()

        self.response_headers: Optional[Iterable[tuple[str, str]]] = None
        self.response: RawResponseMessage | None = None
        self.decompressor: Optional[DeflateBuffer] = None
        # NOTE if headers never come and the server sends a enough data to
        # make us run out of memory the process might be OOM killed
        self._pending_data: bytearray = bytearray()
        self._headers_received = False
        self._auto_decompress = protocol._auto_decompress

        self.body_reader = StreamReader(
            protocol,
            # low_water == window size so pause is never called
            conn.local_settings[Setting.INITIAL_WINDOW_SIZE],
            loop=loop,
        )

        self.closed_event: asyncio.Event = asyncio.Event()

    def transition(self, new_state: StreamState) -> None:
        if (
            new_state not in VALID_TRANSITIONS[self.state]
            and new_state != StreamState.CLOSED
        ):
            raise ProtocolError(
                f"Invalid stream state transition {self.state.name} -> {new_state.name}"
            )
        self.state = new_state
        if new_state == StreamState.CLOSED:
            self.closed_event.set()

    # ------------------------------------------------------------------
    # Data and header reception
    # ------------------------------------------------------------------
    def maybe_reset_window(self) -> None:
        """
        Reset stream-level window.

        Currently, this is done naively.
        """
        # Fine-grained, stream-level flow-control ensures
        # all streams get a fair share of the bandwidth.
        # It requires synchronizing the `Stream`, the protocol, and the payload.
        # Given we are using the HTTP/1.1 payload which resumes the read at a protocol level
        # we can't have this kind of control without changing the `StreamReader` class.
        # Thus, flow-control is not enforced here.
        # Unless the user has different consumers for the streams
        # (e.g., is acting as a proxy for multiple hosts)
        # this doesn't hurt throughput.
        if self.inbound_window < self._inbound_window_initial // 2:
            increment = self._inbound_window_initial - self.inbound_window
            self.inbound_window = self._inbound_window_initial
            self.conn._send_window_update(self.stream_id, increment)

    def receive_data(self, data: bytes, end_stream: bool, limit: int = 0) -> None:
        """Process incoming DATA frame payload."""
        self.inbound_window -= len(data)
        limit = limit or MAX_DECOMPRESS_SIZE

        # --- stream-level flow control refill ---
        self.maybe_reset_window()

        if not self._headers_received:
            # Buffer until we know the content-encoding.
            if len(self._pending_data) + len(data) > limit:
                msg = "Received too much data before headers."
                logging.warning(msg)
                self.conn._send_rst_stream(self.stream_id, ErrorCode.INTERNAL_ERROR)
                return
            self._pending_data.extend(data)
        else:
            # Feed data to the decompressor or directly to the reader.
            if self.decompressor is not None:
                try:
                    more = self.decompressor.feed_data(data)
                    if more is True:
                        msg = f"Uncompressed data contains more than {MAX_DECOMPRESS_SIZE} bytes."
                        raise ContentEncodingError(msg)
                except ContentEncodingError as exc:
                    self.body_reader.set_exception(exc)
                    self.conn._send_rst_stream(self.stream_id, ErrorCode.INTERNAL_ERROR)
                    return
            else:
                self.body_reader.feed_data(data)

        if end_stream:
            self.close()

    def receive_headers(
        self,
        headers: Iterable[HeaderTuple],
        end_stream: bool,
    ) -> None:
        """Process incoming HEADERS frame payload."""
        # HeaderTuple can be tuple[str, str] yet the type hint says
        # it's tuple[bytes, bytes]
        self.response_headers = headers  # type: ignore[assignment]
        self.response = feed_headers(headers)  # type: ignore[arg-type]
        self._headers_received = True

        if self._auto_decompress:
            encoding = self.response.headers.get("content-encoding")
            if encoding:
                # Create a DeflateBuffer wrapping the StreamReader.
                self.decompressor = DeflateBuffer(
                    self.body_reader,
                    encoding=encoding,
                    max_decompress_size=MAX_DECOMPRESS_SIZE,
                )
                # Feed any data that arrived before headers.
                if self._pending_data:
                    try:
                        self.decompressor.feed_data(bytes(self._pending_data))
                    except ContentEncodingError as exc:
                        self.body_reader.set_exception(exc)
                        self.conn._send_rst_stream(
                            self.stream_id, ErrorCode.INTERNAL_ERROR
                        )
                        self._pending_data.clear()
                        return
                    self._pending_data.clear()
            else:
                # No decompression needed; feed pending data directly.
                if self._pending_data:
                    self.body_reader.feed_data(bytes(self._pending_data))
                    self._pending_data.clear()
        else:
            # Autodecompress disabled: feed raw data.
            if self._pending_data:
                self.body_reader.feed_data(bytes(self._pending_data))
                self._pending_data.clear()

        # Deliver the reader as soon as headers are known.
        self.maybe_deliver_response()

        if end_stream:
            self.close()

    def close(self) -> None:
        if self.decompressor is not None:
            try:
                self.decompressor.feed_eof()
            except ContentEncodingError as exc:
                self.body_reader.set_exception(exc)
                self.conn._send_rst_stream(self.stream_id, ErrorCode.INTERNAL_ERROR)
                return
        else:
            self.body_reader.feed_eof()

        if self.state == StreamState.OPEN:
            self.transition(StreamState.HALF_CLOSED_REMOTE)
        elif self.state == StreamState.HALF_CLOSED_LOCAL:
            self.transition(StreamState.CLOSED)
            self.conn._close_stream(self)
        else:
            raise ProtocolError(
                f"Unexpected stream state {self.state.name} for END_STREAM"
            )

    def maybe_deliver_response(self) -> None:
        """Resolve the response future once headers have been received."""
        if (
            self.response_headers is not None
            and self.response is not None
            and not self.response_future.done()
        ):
            self.response_future.set_result((self.response, self.body_reader))

    def cancel(self, reason: Exception) -> None:
        """Cancel any pending response or body data."""
        # Clear buffered data to free memory
        self._pending_data.clear()

        # Fail the response future if it hasn't completed
        if not self.response_future.done():
            self.response_future.set_exception(reason)

        # Fail any pending reads on the body reader
        self.body_reader.set_exception(reason)

        # Mark the stream as closed so no further frames are accepted
        # There are no formal transitions from everything to CLOSED
        # so cancelling bypasses the transition table
        self.transition(StreamState.CLOSED)
