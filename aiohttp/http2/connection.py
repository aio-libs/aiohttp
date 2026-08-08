"""
Complete HTTP/2 client implementation (RFC 7540) for asyncio.

This module provides:
- Frame-level binary wire protocol with debug logging.
- HPACK compression/decompression (using the `hpack` library).
- Full stream state machine (idle -> open -> half‑closed -> closed).
- Multiplexed connection handling (concurrent streams, flow control).
- Server settings tracking (MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, etc.).
- Integration point for aiohttp's TCPConnector via an asyncio.Protocol subclass.

Dependencies:
- asyncio
- struct
- logging
- enum
- hpack  (install with `pip install hpack`)
- collections.defaultdict

Usage:
    Connector replaces `ResponseHandler` with `Http2Protocol`.
"""

import asyncio
import logging
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from hpack import Decoder, Encoder

from .response import Http2Response
from .settings import (
    DEFAULT_SETTINGS,
    FlagData,
    FlagHeaders,
    FlagPing,
    FlagSettings,
    FrameType,
    Setting,
)
from .stream import Stream, StreamState

# ----------------------------------------------------------------------
# Logging – plaintext wire‑format emission for debugging
# ----------------------------------------------------------------------
logger = logging.getLogger("aiohttp.http2.connection")
# logger.setLevel(logging.DEBUG)

FRAME_HEADER_LENGTH = 9  # 9 octets
STREAM_ID_MASK = 0x7FFFFFFF  # to avoid setting the reserved bit to 1


# ----------------------------------------------------------------------
# Connection‑level management
# ----------------------------------------------------------------------
class Http2Connection:
    """Manages a single HTTP/2 connection.

    Handles:
    - Connection preface and SETTINGS handshake.
    - Frame parsing and dispatch.
    - HPACK encoding/decoding.
    - Stream multiplexing and flow control.
    - Server settings tracking.
    """

    def __init__(
        self, transport: asyncio.Transport, loop: asyncio.AbstractEventLoop
    ) -> None:
        self._transport = transport
        self._loop = loop

        # HPACK
        self.hpack_encoder: Encoder = Encoder()
        self.hpack_decoder: Decoder = Decoder()

        # Settings
        self.remote_settings: Dict[Setting, int] = DEFAULT_SETTINGS.copy()
        self.local_settings: Dict[Setting, int] = DEFAULT_SETTINGS.copy()

        # Flow control
        self.session_outbound_window: int = (
            65535  # initial flow control (RFC 7540, 6.9.1)
        )
        self.session_inbound_window: int = 65535
        self._flow_control_updated: asyncio.Event = asyncio.Event()
        self._flow_control_updated.set()  # initially writable

        # Streams
        self.streams: Dict[int, Stream] = {}
        self.next_stream_id: int = 1  # client streams are odd
        self.max_concurrent_streams: int = DEFAULT_SETTINGS[
            Setting.MAX_CONCURRENT_STREAMS
        ]
        self._pending_streams: List[asyncio.Future[Stream]] = []
        self._last_peer_stream_id: int = (
            0  # highest server‑initiated stream (even, unused for client)
        )

        # Frame buffers
        self._frame_buffer: bytearray = bytearray()

        # GOAWAY state
        self._goaway_received: bool = False
        self._goaway_sent: bool = False
        self._last_stream_id: int = 0
        self._error_code: int = 0

        # Closed streams cleanup
        self._closed_streams: Set[int] = set()

    # -------------------- Transport callbacks --------------------
    def data_received(self, data: bytes) -> None:
        """Assemble frames from the byte stream and dispatch them."""
        self._frame_buffer.extend(data)
        # Consume complete frames while enough bytes for the header exist
        while len(self._frame_buffer) >= FRAME_HEADER_LENGTH:
            # Parse 24-bit length, 8-bit type, 8-bit flags, 32-bit stream ID
            length = (
                self._frame_buffer[0] << 16
                | self._frame_buffer[1] << 8
                | self._frame_buffer[2]
            )
            frame_type_val = self._frame_buffer[3]
            flags = self._frame_buffer[4]
            stream_id = struct.unpack("!I", self._frame_buffer[5:9])[0] & STREAM_ID_MASK

            if len(self._frame_buffer) < FRAME_HEADER_LENGTH + length:
                break  # incomplete frame; wait for more data

            payload = bytes(
                self._frame_buffer[FRAME_HEADER_LENGTH : FRAME_HEADER_LENGTH + length]
            )
            del self._frame_buffer[: FRAME_HEADER_LENGTH + length]

            # invalid frames cause a value error
            if 0 <= frame_type_val <= 9:
                logger.debug(
                    "<- %s stream=%d flags=0x%02x len=%d",
                    FrameType(frame_type_val).name,
                    stream_id,
                    flags,
                    length,
                )

            self._dispatch_frame(frame_type_val, flags, stream_id, payload)

    def eof_received(self) -> bool:
        logger.debug("EOF received from server")
        self.close()
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        logger.debug(f"Connection lost: {exc}")
        # Cancel all pending streams (including those in the queue)
        for stream in list(self.streams.values()):
            if not stream.response_future.done():
                stream.response_future.set_exception(ConnectionError("Connection lost"))
        for fut in self._pending_streams:
            fut.set_exception(ConnectionError("Connection lost"))
        self.streams.clear()

    # -------------------- Frame dispatch --------------------
    def _dispatch_frame(
        self, frame_type: int, flags: int, stream_id: int, payload: bytes
    ) -> None:
        if frame_type == FrameType.DATA:
            self._handle_data_frame(flags, stream_id, payload)
        elif frame_type == FrameType.HEADERS:
            self._handle_headers_frame(flags, stream_id, payload)
        elif frame_type in {
            FrameType.PRIORITY,
            FrameType.PUSH_PROMISE,
            FrameType.CONTINUATION,
        }:
            logger.warning("%d frame ignored (not implemented)", frame_type)
        elif frame_type == FrameType.RST_STREAM:
            self._handle_rst_stream_frame(flags, stream_id, payload)
        elif frame_type == FrameType.SETTINGS:
            self._handle_settings_frame(flags, stream_id, payload)
        elif frame_type == FrameType.PING:
            self._handle_ping_frame(flags, stream_id, payload)
        elif frame_type == FrameType.GOAWAY:
            self._handle_goaway_frame(flags, stream_id, payload)
        elif frame_type == FrameType.WINDOW_UPDATE:
            self._handle_window_update_frame(flags, stream_id, payload)
        else:
            logger.warning("Ignoring unknown frame type %d", frame_type)

    # ---------- Individual frame handlers ----------
    def _handle_data_frame(self, flags: int, stream_id: int, payload: bytes) -> None:
        stream = self.streams.get(stream_id)
        if stream is None:
            if stream_id > self._last_peer_stream_id:
                self._send_rst_stream(stream_id, 1)  # PROTOCOL_ERROR
            return

        pad_length = 0
        pos = 0
        if flags & FlagData.PADDED:
            pad_length = payload[0]
            pos = 1

        # padding might be too long
        data = payload[pos : len(payload) - pad_length]
        end_stream = bool(flags & FlagData.END_STREAM)

        # Update session flow control
        self.session_inbound_window -= len(data)
        # hardcoded values
        if self.session_inbound_window < 32768:
            self._send_window_update(0, 65535 - self.session_inbound_window)
            self.session_inbound_window = 65535

        stream.receive_data(data, end_stream)

    def _handle_headers_frame(self, flags: int, stream_id: int, payload: bytes) -> None:
        if flags & FlagHeaders.PRIORITY:
            # Exclusive flag + stream dependency + weight
            # exclude priority data
            payload = payload[5:]

        # Decode headers with HPACK
        try:
            headers = self.hpack_decoder.decode(payload)
        except Exception as exc:  # too general?
            logger.error(f"HPACK decode error: {exc}")
            self._send_rst_stream(stream_id, 1)  # PROTOCOL_ERROR
            return

        end_stream = bool(flags & FlagHeaders.END_STREAM)

        stream = self.streams.get(stream_id)

        if stream is None:
            logger.error("Unknown stream_id: %d", stream_id)
        else:
            stream.receive_headers(headers, end_stream)

    def _handle_rst_stream_frame(
        self, flags: int, stream_id: int, payload: bytes
    ) -> None:
        del flags  # rst doesn't use flags

        error_code = struct.unpack("!I", payload)[0]
        stream = self.streams.get(stream_id)
        if stream:
            stream.transition(StreamState.CLOSED)
            if not stream.response_future.done():
                stream.response_future.set_exception(
                    RuntimeError(f"Stream reset by server (code={error_code})")
                )
            self._close_stream(stream)

    def _handle_settings_frame(
        self, flags: int, stream_id: int, payload: bytes
    ) -> None:
        """Process SETTINGS frame (6.5)"""
        if flags & FlagSettings.ACK:
            logger.debug("Received SETTINGS ACK")
            return  # Our settings were acknowledged
        if stream_id != 0:
            logger.error(
                "SETTING frame received after the first stream in violation of the protocol standard (RFC-9113, 3.4)"
            )
            self._protocol_error()
            return

        if len(payload) % 6 != 0:
            logger.error("SETTINGS payload length not a multiple of 6")
            self._protocol_error()
            return

        # Parse key‑value pairs
        for i in range(0, len(payload), 6):
            identifier, value = struct.unpack("!H I", payload[i : i + 6])
            if identifier < 0 or identifier > 9:
                logger.warning("Unknown setting identifier %d", identifier)
                continue
            setting = Setting(identifier)
            old_value = self.remote_settings.get(setting, value)
            self.remote_settings[setting] = value
            logger.info(f"Server SETTINGS: {setting.name} = {value}")

            # React to certain settings
            if setting == Setting.INITIAL_WINDOW_SIZE and value != old_value:
                # might become negative
                # send WINDOW_UPDATE
                delta = value - old_value
                for s in self.streams.values():
                    s.outbound_window += delta
            elif setting == Setting.MAX_CONCURRENT_STREAMS:
                self.max_concurrent_streams = value
                self._maybe_unblock_streams()
            elif setting == Setting.HEADER_TABLE_SIZE:
                self.hpack_encoder.header_table_size = value

        # Acknowledge settings
        self._send_settings_ack()

    def _handle_ping_frame(self, flags: int, stream_id: int, payload: bytes) -> None:
        if stream_id != 0:
            self._protocol_error()
            return
        if flags & FlagPing.ACK:
            logger.debug("Received PING ACK")
        else:
            # Respond with ACK
            logger.debug("Received PING, sending ACK")
            self._send_ping(ack=True, opaque_data=payload)

    def _handle_goaway_frame(self, flags: int, stream_id: int, payload: bytes) -> None:
        del flags, stream_id  # interface

        self._goaway_received = True
        last_stream_id, error_code = struct.unpack("!I I", payload[:8])
        extra = payload[8:]
        self._last_stream_id = last_stream_id
        self._error_code = error_code
        logger.info(
            "GOAWAY received: last_stream=%d, error=%d, extra=%s",
            last_stream_id,
            error_code,
            extra.decode(),
        )
        # Cancel streams with higher IDs
        for sid, stream in list(self.streams.items()):
            if sid > last_stream_id:
                if not stream.response_future.done():
                    stream.response_future.set_exception(
                        ConnectionError("GOAWAY received")
                    )
                self._close_stream(stream)
        # clear pending streams?

    def _handle_window_update_frame(
        self, flags: int, stream_id: int, payload: bytes
    ) -> None:
        increment = struct.unpack("!I", payload)[0]
        if stream_id == 0:
            # Session window update
            self.session_outbound_window += increment
        else:
            stream = self.streams.get(stream_id)
            if stream:
                stream.outbound_window += increment
        # Wake up any writer waiting for flow control
        self._flow_control_updated.set()

    # -------------------- Frame sending helpers --------------------
    def _send_frame(
        self,
        frame_type: FrameType,
        flags: int,
        stream_id: int,
        payload: bytes = b"",
    ) -> None:
        length = len(payload) & 0x00FFFFFF  # 24 bits -> 3 bytes
        header = struct.pack("!I", length)[
            1:
        ] + struct.pack(  # drop the first (most‑significant) byte → 3 bytes
            "!B B I", frame_type, flags, stream_id
        )

        logger.debug(
            f"-> FRAME type={frame_type.name:>15} flags=0x{flags:02x} "
            f"stream_id={stream_id:<5} length={len(payload)}"
        )
        self._transport.write(header + payload)

    def _send_settings_ack(self) -> None:
        self._send_frame(FrameType.SETTINGS, FlagSettings.ACK, 0)

    def _send_ping(self, ack: bool = False, opaque_data: bytes = b"\x00" * 8) -> None:
        flags = FlagPing.ACK if ack else 0
        self._send_frame(FrameType.PING, flags, 0, opaque_data)

    def _send_goaway(self, last_stream_id: int, error_code: int) -> None:
        payload = struct.pack("!I I", last_stream_id, error_code)
        self._send_frame(FrameType.GOAWAY, 0, 0, payload)
        self._goaway_sent = True

    def _send_rst_stream(self, stream_id: int, error_code: int) -> None:
        payload = struct.pack("!I", error_code)
        self._send_frame(FrameType.RST_STREAM, 0, stream_id, payload)

    def _send_window_update(self, stream_id: int, increment: int) -> None:
        payload = struct.pack("!I", increment)
        self._send_frame(FrameType.WINDOW_UPDATE, 0, stream_id, payload)

    # -------------------- Stream lifecycle --------------------
    def _close_stream(self, stream: Stream) -> None:
        self.streams.pop(stream.stream_id, None)
        self._closed_streams.add(stream.stream_id)
        # Release stream concurrency slot
        self._maybe_unblock_streams()

    def _maybe_unblock_streams(self) -> None:
        """Create streams from pending requests if concurrency allows."""
        while self._pending_streams and len(self.streams) < self.max_concurrent_streams:
            fut = self._pending_streams.pop(0)
            if not fut.done():
                stream = self._create_stream_internal()
                fut.set_result(stream)

    def _create_stream_internal(self) -> Stream:
        sid = self.next_stream_id
        self.next_stream_id += 2  # next client stream
        stream = Stream(sid, self, self._loop)
        self.streams[sid] = stream
        return stream

    async def create_stream(self) -> Stream:
        """Return a new client stream, waiting if concurrency limit is reached."""
        if self._goaway_sent or self._goaway_received:
            raise ConnectionError("Connection is shutting down")
        if len(self.streams) < self.max_concurrent_streams:
            return self._create_stream_internal()
        # Queue the request
        fut: asyncio.Future[Stream] = self._loop.create_future()
        self._pending_streams.append(fut)
        return await fut

    # -------------------- Request sending --------------------
    async def send_data(
        self, stream: Stream, data: bytes, end_stream: bool = True
    ) -> None:
        """Asynchronously send DATA frames, respecting flow control windows."""
        max_frame_size = self.remote_settings[Setting.MAX_FRAME_SIZE]
        offset = 0
        total = len(data)

        while offset < total:
            # Wait until both session and stream windows have capacity
            while stream.outbound_window <= 0 or self.session_outbound_window <= 0:
                self._flow_control_updated.clear()
                await self._flow_control_updated.wait()

            chunk_size = min(
                max_frame_size,
                stream.outbound_window,
                self.session_outbound_window,
                total - offset,
            )
            flags = 0
            if offset + chunk_size >= total and end_stream:
                flags |= FlagData.END_STREAM

                if stream.state == StreamState.OPEN:
                    stream.transition(StreamState.HALF_CLOSED_LOCAL)
                elif stream.state == StreamState.HALF_CLOSED_REMOTE:
                    stream.transition(StreamState.CLOSED)
                    self._close_stream(stream)
                # else: error

            self._send_frame(
                FrameType.DATA,
                flags,
                stream.stream_id,
                data[offset : offset + chunk_size],
            )
            stream.outbound_window -= chunk_size
            self.session_outbound_window -= chunk_size
            offset += chunk_size

            # there is space available
            if self.session_outbound_window and stream.outbound_window:
                self._flow_control_updated.set()

    async def send_request(
        self,
        stream: Stream,
        method: str,
        url: Any,  # Usually a yarl.URL, but abstracted for mocking
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
    ) -> None:
        """Send HEADERS and optional DATA frames for a stream."""
        # :path needs the query as well
        path_and_query = url.path
        if url.query:
            path_and_query += "?" + url.raw_query_string

        # Build pseudo‑headers
        req_headers = [
            (":method", method),
            (":path", path_and_query),
            (":scheme", url.scheme),
            (":authority", url.host),
        ]

        for name, value in headers:
            lname = name.lower()
            # HTTP/2 forbids connection-specific headers and the Host header
            if lname in (
                "host",
                "connection",
                "keep-alive",
                "proxy-connection",
                "transfer-encoding",
                "upgrade",
            ):
                continue
            req_headers.append((lname, value))

        hdrs = self.hpack_encoder.encode(req_headers)
        end_stream = body is None or len(body) == 0
        flags = FlagHeaders.END_HEADERS

        # stream transitions
        stream.transition(StreamState.OPEN)
        if end_stream:
            flags |= FlagHeaders.END_STREAM
            stream.transition(StreamState.HALF_CLOSED_LOCAL)

        self._send_frame(FrameType.HEADERS, flags, stream.stream_id, hdrs)

        if body:
            await self.send_data(stream, body, end_stream=True)

    # -------------------- Connection lifecycle --------------------
    def initiate_connection(self) -> None:
        """Send the connection preface and initial SETTINGS."""
        # Connection preface (RFC 7540, 3.5)
        self._transport.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

        # Send initial SETTINGS (our preferences)
        settings_payload = struct.pack(
            "!H I", Setting.ENABLE_PUSH, 0  # disable server push
        )
        self._send_frame(FrameType.SETTINGS, 0, 0, settings_payload)

        # Update local HPACK table size if needed
        self.hpack_encoder.header_table_size = self.local_settings[
            Setting.HEADER_TABLE_SIZE
        ]

        logger.debug("Connection preface and initial SETTINGS sent")

    def _protocol_error(self) -> None:
        self._send_goaway(0, 1)  # PROTOCOL_ERROR
        self._transport.close()

    # -------------------- Shutdown --------------------
    def close(self) -> None:
        """Perform graceful shutdown."""
        self._transport.close()

    @property
    def should_close(self) -> bool:
        return self._goaway_sent or self._goaway_received

    def is_connected(self) -> bool:
        return not self._transport.is_closing()


# ----------------------------------------------------------------------
# Protocol wrapper for asyncio.Transport (connector integration)
# ----------------------------------------------------------------------
class Http2Protocol(asyncio.Protocol):
    """asyncio.Protocol subclass that bridges transport and Http2Connection.

    This replaces aiohttp's ResponseHandler in the connector.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._connection: Optional[Http2Connection] = None
        self._closed_future: asyncio.Future[None] = loop.create_future()
        self.transport: Optional[asyncio.Transport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self._connection = Http2Connection(self.transport, self._loop)  # type: ignore[arg-type]
        self._connection.initiate_connection()

    def data_received(self, data: bytes) -> None:
        if self._connection:
            self._connection.data_received(data)

    def eof_received(self) -> bool:
        if self._connection:
            self._connection.eof_received()
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._connection:
            self._connection.connection_lost(exc)
        if not self._closed_future.done():
            self._closed_future.set_result(None)

    # Compatibility with connector's expectations
    @property
    def should_close(self) -> bool:
        return self._connection.should_close if self._connection else False

    def is_connected(self) -> bool:
        return self._connection.is_connected() if self._connection else False

    @property
    def closed(self) -> asyncio.Future[None]:
        return self._closed_future

    async def send(
        self,
        method: str,
        url: Any,
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
    ) -> Http2Response:
        """Send an HTTP/2 request and return a compatible response."""
        if self._connection is None:
            raise RuntimeError("Connection not established")

        # Obtain a stream from the pool
        stream = await self._connection.create_stream()

        await self._connection.send_request(stream, method, url, headers, body)

        # Wait for the response future to be set by the stream when complete
        _, resp_headers, resp_body = await stream.response_future

        response = Http2Response(
            headers=resp_headers,
            body=resp_body,
            method=method,
            url=url,
        )

        return response

    def close(self) -> None:
        if self._connection:
            self._connection.close()
        self.transport = None

    def abort(self) -> None:
        self.close()
