import asyncio
from enum import IntEnum
from typing import List, Optional, Tuple

from .errors import ProtocolError
from .settings import Setting


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
# Added missing RESERVED_REMOTE from IDLE
VALID_TRANSITIONS = {
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
    StreamState.CLOSED: set(),  # terminal state
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
        "request_body",
        "response_headers",
        "response_data",
        "closed_event",
    )

    def __init__(self, stream_id: int, conn, loop) -> None:
        self.stream_id = stream_id
        self.state = StreamState.IDLE
        self.conn = conn

        # Flow‑control windows (stream‑level only; session window managed by connection)
        self.outbound_window = conn.remote_settings[Setting.INITIAL_WINDOW_SIZE]
        self.inbound_window = conn.local_settings[Setting.INITIAL_WINDOW_SIZE]

        self.response_future: asyncio.Future[
            Tuple[int, List[Tuple[str, str]], bytes]
        ] = loop.create_future()

        self.response_headers: Optional[List[Tuple[str, str]]] = None
        self.response_data = bytearray()

        # Event notified when the stream enters CLOSED state
        self.closed_event = asyncio.Event()

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
    # Data and header reception – state transitions are now **conditional**
    # on the current state, matching RFC 7540/9113 exactly.
    # ------------------------------------------------------------------
    def receive_data(self, data: bytes, end_stream: bool) -> None:
        """Process incoming DATA frame payload."""
        self.inbound_window -= len(data)
        self.response_data.extend(data)

        if end_stream:
            # Correct transition depending on current state
            if self.state == StreamState.OPEN:
                self.transition(StreamState.HALF_CLOSED_REMOTE)
            elif self.state == StreamState.HALF_CLOSED_LOCAL:
                self.transition(StreamState.CLOSED)
                self.conn._close_stream(self)  # clean up connection map
            else:
                raise ProtocolError(
                    f"Unexpected stream state {self.state.name} for END_STREAM"
                )

            self.maybe_deliver_response()

    def maybe_deliver_response(self):
        # Deliver the full response once headers have been received
        if self.response_headers is not None and not self.response_future.done():
            self.response_future.set_result(
                (self.stream_id, self.response_headers, bytes(self.response_data))
            )

    def receive_headers(self, headers: List[Tuple[str, str]], end_stream: bool) -> None:
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

        # else: stream remains in OPEN (or HALF_CLOSED_LOCAL), headers stored for later delivery.
