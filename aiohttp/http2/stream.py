import asyncio
from enum import IntEnum
from typing import TYPE_CHECKING, Dict, Iterable, Optional, Set, Tuple

from hpack import HeaderTuple

from .errors import ProtocolError
from .settings import Setting

if TYPE_CHECKING:
    from .connection import Http2Connection


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


# ----------------------------------------------------------------------
# Stream object – multiplexed stream handle
# ----------------------------------------------------------------------
class Stream:
    """A single HTTP/2 stream.

    Manages state, flow control, and provides a future for the response.
    """

    __slots__ = (
        "stream_id",
        "state",
        "conn",
        "outbound_window",
        "inbound_window",
        "response_future",
        "response_headers",
        "response_data",
        "closed_event",
        "_inbound_window_initial",
    )

    def __init__(
        self, stream_id: int, conn: "Http2Connection", loop: asyncio.AbstractEventLoop
    ) -> None:
        self.stream_id = stream_id
        self.state = StreamState.IDLE
        self.conn = conn

        # Flow‑control windows (stream‑level only)
        self.outbound_window: int = conn.remote_settings[Setting.INITIAL_WINDOW_SIZE]
        self.inbound_window: int = conn.local_settings[Setting.INITIAL_WINDOW_SIZE]
        # Store the initial inbound window for refilling without hard-coded values
        self._inbound_window_initial: int = self.inbound_window

        self.response_future: asyncio.Future[
            Tuple[int, Iterable[HeaderTuple] | Iterable[Tuple[str, str]], bytes]
        ] = loop.create_future()

        self.response_headers: Optional[
            Iterable[HeaderTuple] | Iterable[Tuple[str, str]]
        ] = None
        self.response_data: bytearray = bytearray()

        # Event notified when the stream enters CLOSED state
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
    def receive_data(self, data: bytes, end_stream: bool) -> None:
        """Process incoming DATA frame payload."""
        self.inbound_window -= len(data)
        self.response_data.extend(data)

        # --- stream-level flow control refill ---
        if self.inbound_window < self._inbound_window_initial // 2:
            increment = self._inbound_window_initial - self.inbound_window
            self.inbound_window = self._inbound_window_initial
            # Use the connection’s helper to send the WINDOW_UPDATE frame
            self.conn._send_window_update(self.stream_id, increment)

        if end_stream:
            if self.state == StreamState.OPEN:
                self.transition(StreamState.HALF_CLOSED_REMOTE)
            elif self.state == StreamState.HALF_CLOSED_LOCAL:
                self.transition(StreamState.CLOSED)
                self.conn._close_stream(self)
            else:
                raise ProtocolError(
                    f"Unexpected stream state {self.state.name} for END_STREAM"
                )

            self.maybe_deliver_response()

    def maybe_deliver_response(self) -> None:
        # Deliver the full response once headers have been received
        if self.response_headers is not None and not self.response_future.done():
            self.response_future.set_result(
                (self.stream_id, self.response_headers, bytes(self.response_data))
            )

    def receive_headers(
        self,
        headers: Iterable[HeaderTuple] | Iterable[Tuple[str, str]],
        end_stream: bool,
    ) -> None:
        """Process incoming HEADERS frame payload."""
        self.response_headers = headers

        if end_stream:
            if self.state == StreamState.OPEN:
                self.transition(StreamState.HALF_CLOSED_REMOTE)
            elif self.state == StreamState.HALF_CLOSED_LOCAL:
                self.transition(StreamState.CLOSED)
                self.conn._close_stream(self)
            else:
                raise ProtocolError(
                    f"Unexpected stream state {self.state.name} for END_STREAM on headers"
                )
            self.maybe_deliver_response()
