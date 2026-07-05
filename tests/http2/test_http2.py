"""
Test suite for aiohttp.http2

Categories:
- integration: against a real httpbin server (skipped, requires network)
- unit / protocol: black‑box frame‑level RFC compliance
- unit / misc: race conditions, deadlocks, edge cases
- unit / interface: high‑level features (JSON, redirects, compression, etc.)
"""

import asyncio
import gzip
import json
import struct
from typing import List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
from hpack import Encoder

from aiohttp.http2.connection import Http2Connection, Http2Protocol
from aiohttp.http2.errors import ProtocolError
from aiohttp.http2.response import Http2Response
from aiohttp.http2.settings import (
    FlagData,
    FlagHeaders,
    FlagPing,
    FlagSettings,
    FrameType,
    Setting,
)
from aiohttp.http2.stream import StreamState


# ----------------------------------------------------------------------
# Helper: minimal URL mock
# ----------------------------------------------------------------------
def url_mock(path="/"):
    """Create a simple URL-like object expected by the implementation."""
    return type("URL", (), {"scheme": "https", "host": "example.com", "path": path})


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture
def mock_transport():
    """Return a mock asyncio.Transport that records writes."""
    t = MagicMock(spec=asyncio.Transport)
    t.is_closing.return_value = False
    t.write = MagicMock()
    t.close = MagicMock()
    return t


@pytest.fixture
def event_loop():
    """Create a new event loop for each test."""
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest.fixture
# async def connection(mock_transport, event_loop):
async def connection(mock_transport):
    """Set up Http2Connection with mock transport, send preface, and clear write log."""
    event_loop = asyncio.get_running_loop()

    conn = Http2Connection(mock_transport, event_loop)
    conn.initiate_connection()
    mock_transport.write.reset_mock()  # discard preface + initial SETTINGS
    return conn, mock_transport


@pytest.fixture
# async def protocol(mock_transport, event_loop):
async def protocol(mock_transport):
    """Create Http2Protocol and simulate connection_made."""
    event_loop = asyncio.get_running_loop()
    proto = Http2Protocol(event_loop)
    proto.connection_made(mock_transport)
    mock_transport.write.reset_mock()
    return proto, mock_transport


# ----------------------------------------------------------------------
# Frame construction helpers
# ----------------------------------------------------------------------
# one could argue that we could add these static methods to the implementation
def frame_header(length: int, ftype: FrameType, flags: int, stream_id: int) -> bytes:
    # 24-bit length (3 bytes) + type + flags + stream_id
    return struct.pack("!I", length)[1:] + struct.pack(
        "!B B I", ftype, flags, stream_id
    )


def build_settings_frame(
    settings_pairs: List[Tuple[Setting, int]] = None, ack: bool = False
) -> bytes:
    payload = b""
    if not ack and settings_pairs:
        for setting_id, value in settings_pairs:
            payload += struct.pack("!H I", setting_id, value)
    flags = FlagSettings.ACK if ack else 0
    return frame_header(len(payload), FrameType.SETTINGS, flags, 0) + payload


def build_headers_frame(
    stream_id: int,
    headers: List[Tuple[str, str]],
    end_headers: bool = True,
    end_stream: bool = False,
    priority: Optional[bytes] = None,
) -> bytes:
    encoder = Encoder()
    header_block = encoder.encode(headers)
    flags = 0
    if end_headers:
        flags |= FlagHeaders.END_HEADERS
    if end_stream:
        flags |= FlagHeaders.END_STREAM
    if priority is not None:
        flags |= FlagHeaders.PRIORITY
        header_block = priority + header_block
    return (
        frame_header(len(header_block), FrameType.HEADERS, flags, stream_id)
        + header_block
    )


def build_data_frame(
    stream_id: int, data: bytes, end_stream: bool = False, pad: bool = False
) -> bytes:
    payload = data
    flags = 0
    if end_stream:
        flags |= FlagData.END_STREAM
    if pad:
        pad_len = 1  # minimal padding for test
        payload = bytes([pad_len]) + data + b"\x00" * pad_len
        flags |= FlagData.PADDED
    return frame_header(len(payload), FrameType.DATA, flags, stream_id) + payload


def build_rst_stream(stream_id: int, error_code: int = 0) -> bytes:
    payload = struct.pack("!I", error_code)
    return frame_header(4, FrameType.RST_STREAM, 0, stream_id) + payload


def build_goaway(last_stream_id: int, error_code: int, extra: bytes = b"") -> bytes:
    payload = struct.pack("!I I", last_stream_id, error_code) + extra
    return frame_header(len(payload), FrameType.GOAWAY, 0, 0) + payload


def build_window_update(stream_id: int, increment: int) -> bytes:
    payload = struct.pack("!I", increment)
    return frame_header(4, FrameType.WINDOW_UPDATE, 0, stream_id) + payload


def build_ping(ack: bool = False, opaque: bytes = b"\x00" * 8) -> bytes:
    flags = FlagPing.ACK if ack else 0
    return frame_header(8, FrameType.PING, flags, 0) + opaque


@pytest.mark.asyncio
async def test_incomplete_frame(connection):
    connection, _ = connection
    frame = b"111111111"
    connection.data_received(frame)
    assert connection._frame_buffer == frame


# ======================================================================
# UNIT TESTS
# ======================================================================


# ----------------------------------------------------------------------
# 1. Protocol compliance (black‑box, frame‑by‑frame)
# ----------------------------------------------------------------------
class TestProtocolCompliance:
    @pytest.mark.asyncio
    async def test_receive_settings_updates_remote_and_acks(
        self, connection, mock_transport
    ):
        conn, transport = connection
        # Send server SETTINGS (HEADER_TABLE_SIZE=8192, MAX_CONCURRENT_STREAMS=50)
        frame = build_settings_frame(
            [
                (Setting.HEADER_TABLE_SIZE, 8192),
                (Setting.MAX_CONCURRENT_STREAMS, 50),
            ]
        )
        conn.data_received(frame)
        assert conn.remote_settings[Setting.HEADER_TABLE_SIZE] == 8192
        assert conn.remote_settings[Setting.MAX_CONCURRENT_STREAMS] == 50
        # Must have sent an ACK
        assert any(
            call[0][0][3:4] == FrameType.SETTINGS.to_bytes(1, "big")
            and call[0][0][4] & FlagSettings.ACK
            for call in transport.write.call_args_list
        )

    @pytest.mark.asyncio
    async def test_receive_headers_for_new_stream(self, connection, mock_transport):
        conn, _ = connection
        # Create a stream from client side first (simulate request sent)
        stream = await conn.create_stream()
        await conn.send_request(stream, "GET", url_mock(), [])
        stream.state = StreamState.OPEN  # skip real send, just set state

        # Send response HEADERS with END_STREAM
        headers = [(":status", "200"), ("content-type", "text/plain")]
        frame = build_headers_frame(stream.stream_id, headers, end_stream=True)
        conn.data_received(frame)

        # Verify stream received response
        assert stream.response_future.done()
        sid, resp_headers, body = stream.response_future.result()
        assert sid == stream.stream_id
        assert dict(resp_headers)[":status"] == "200"
        assert body == b""

    @pytest.mark.asyncio
    async def test_receive_data_flow_control(self, connection, mock_transport):
        conn, transport = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN  # assume request already sent

        # Send DATA with some bytes
        data = b"hello"
        frame = build_data_frame(stream.stream_id, data, end_stream=False)
        initial_window = conn.session_inbound_window
        conn.data_received(frame)
        assert conn.session_inbound_window == initial_window - len(data)
        # Should trigger WINDOW_UPDATE when below threshold (32768)
        # Because initial window is 65535 and we just consumed 5, still above threshold
        assert not any(
            b"WINDOW_UPDATE" in call.args[0] for call in transport.write.call_args_list
        )

        # Send more data to drop below 32768
        big_data = b"x" * 40000
        frame2 = build_data_frame(stream.stream_id, big_data, end_stream=False)
        conn.data_received(frame2)
        # Now session window should have triggered an update
        updates = [
            call.args[0]
            for call in transport.write.call_args_list
            if FrameType.WINDOW_UPDATE.to_bytes(1, "big") in call.args[0]
        ]
        assert len(updates) >= 1

    @pytest.mark.asyncio
    async def test_rst_stream_handling(self, connection):
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN

        frame = build_rst_stream(stream.stream_id, error_code=0x8)  # CANCEL
        conn.data_received(frame)

        assert stream.state == StreamState.CLOSED
        assert stream.response_future.done()
        with pytest.raises(RuntimeError):
            stream.response_future.result()
        assert stream.stream_id not in conn.streams

    @pytest.mark.asyncio
    async def test_goaway_cancels_higher_streams(self, connection):
        conn, _ = connection
        # create three streams (1,3,5)
        s1 = await conn.create_stream()
        s3 = await conn.create_stream()
        s5 = await conn.create_stream()
        s1.state = s3.state = s5.state = StreamState.OPEN

        # GOAWAY with last_stream_id = 3
        frame = build_goaway(last_stream_id=3, error_code=0)
        conn.data_received(frame)

        # s1 (1) and s3 (3) should be unaffected, s5 (5) cancelled
        assert s1.stream_id in conn.streams
        assert s3.stream_id in conn.streams
        assert s5.stream_id not in conn.streams
        assert s5.response_future.exception() is not None

    @pytest.mark.asyncio
    async def test_ping_ack(self, connection, mock_transport):
        conn, transport = connection
        frame = build_ping(ack=False, opaque=b"12345678")
        conn.data_received(frame)
        # Expect ACK sent back with same data
        acks = []
        for call in transport.write.call_args_list:
            arg = call.args[0]
            if FrameType.PING.to_bytes(1, "big") in arg and arg[4] & FlagPing.ACK:
                acks.append(arg)
        assert len(acks) == 1
        assert b"12345678" in acks[0]

    @pytest.mark.asyncio
    async def test_max_concurrent_streams_blocking(self, connection):
        conn, _ = connection
        conn.max_concurrent_streams = 1
        s1 = await conn.create_stream()
        # second stream should block
        create_task = asyncio.ensure_future(conn.create_stream())
        await asyncio.sleep(0.01)
        assert not create_task.done()
        # close s1 to release slot
        conn._close_stream(s1)
        s2 = await create_task
        assert s2.stream_id > s1.stream_id
        assert len(conn.streams) == 1

    @pytest.mark.asyncio
    async def test_unknown_frame_ignored(self, connection):
        conn, _ = connection
        # send frame type 0x1a (unused)
        frame = frame_header(0, 0x1A, 0, 0)
        conn.data_received(frame)
        # Should not raise, connection stays intact
        assert not conn._goaway_sent

    @pytest.mark.asyncio
    async def test_bad_hpack_triggers_protocol_error(self, connection):
        conn, transport = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        # corrupted headers
        payload = b"\xff\xff\xff"
        frame = (
            frame_header(
                len(payload),
                FrameType.HEADERS,
                FlagHeaders.END_HEADERS,
                stream.stream_id,
            )
            + payload
        )
        conn.data_received(frame)
        # Should have sent RST_STREAM and/or GOAWAY
        rst = any(
            call.args[0][3:4] == FrameType.RST_STREAM.to_bytes(1, "big")
            for call in transport.write.call_args_list
        )
        goaway = any(
            call.args[0][3:4] == FrameType.GOAWAY.to_bytes(1, "big")
            for call in transport.write.call_args_list
        )
        assert rst or goaway

    @pytest.mark.asyncio
    async def test_data_frame_with_padding(self, connection):
        """Cover DATA frame with PADDED flag."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        # padded data: pad length 1, data 'x', zero padding byte
        frame = build_data_frame(stream.stream_id, b"x", pad=True)
        conn.data_received(frame)
        assert stream.response_data == b"x"

    @pytest.mark.asyncio
    async def test_headers_frame_with_priority(self, connection):
        """Cover HEADERS frame with PRIORITY flag."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        # priority block: exclusive (1 byte) + dependency (4 bytes) + weight (1 byte)
        priority_data = b"\x00\x00\x00\x00\x10"
        headers = [(":status", "200")]
        frame = build_headers_frame(
            stream.stream_id,
            headers,
            end_headers=True,
            end_stream=True,
            priority=priority_data,
        )
        conn.data_received(frame)
        assert stream.response_future.done()
        assert stream.response_headers is not None

    @pytest.mark.asyncio
    async def test_rst_stream_for_unknown_stream(self, connection):
        """RST_STREAM on an unknown stream ID is silently ignored."""
        conn, _ = connection
        frame = build_rst_stream(999, error_code=0)
        conn.data_received(frame)  # must not raise

    @pytest.mark.asyncio
    async def test_rst_stream_when_future_done(self, connection):
        """RST_STREAM when response future already completed (else branch of line 256)."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        stream.response_future.set_result((stream.stream_id, [], b""))
        frame = build_rst_stream(stream.stream_id, error_code=0)
        conn.data_received(frame)
        assert stream.state == StreamState.CLOSED

    @pytest.mark.asyncio
    async def test_receive_settings_ack(self, connection):
        """Receive SETTINGS ACK (should be a no‑op)."""
        conn, _ = connection
        frame = build_settings_frame(ack=True)
        conn.data_received(frame)  # no crash

    @pytest.mark.asyncio
    async def test_settings_on_nonzero_stream(self, connection, mock_transport):
        """SETTINGS frame on stream_id != 0 triggers GOAWAY."""
        conn, transport = connection
        frame = frame_header(0, FrameType.SETTINGS, 0, 5)  # stream 5
        conn.data_received(frame)
        assert any(
            call[0][0][3:4] == FrameType.GOAWAY.to_bytes(1, "big")
            for call in transport.write.call_args_list
        )

    @pytest.mark.asyncio
    async def test_settings_invalid_payload_length(self, connection, mock_transport):
        """SETTINGS payload not a multiple of 6 triggers protocol error."""
        conn, transport = connection
        payload = b"\x00\x01\x02"  # 3 bytes
        frame = frame_header(len(payload), FrameType.SETTINGS, 0, 0) + payload
        conn.data_received(frame)
        assert any(
            call[0][0][3:4] == FrameType.GOAWAY.to_bytes(1, "big")
            for call in transport.write.call_args_list
        )

    @pytest.mark.asyncio
    async def test_settings_initial_window_size_update(self, connection):
        """INITIAL_WINDOW_SIZE setting updates stream windows."""
        conn, _ = connection
        stream = await conn.create_stream()
        old_window = stream.outbound_window
        frame = build_settings_frame([(Setting.INITIAL_WINDOW_SIZE, 131072)])
        conn.data_received(frame)
        assert stream.outbound_window == old_window + (131072 - 65535)

    @pytest.mark.asyncio
    async def test_settings_header_table_size(self, connection):
        """HEADER_TABLE_SIZE setting is processed."""
        conn, _ = connection
        frame = build_settings_frame([(Setting.HEADER_TABLE_SIZE, 4096)])
        conn.data_received(frame)
        # internal effect on encoder, just confirm no crash

    @pytest.mark.asyncio
    async def test_ping_on_nonzero_stream(self, connection, mock_transport):
        """PING on non‑zero stream triggers GOAWAY."""
        conn, transport = connection
        frame = frame_header(8, FrameType.PING, 0, 1) + b"\x00" * 8
        conn.data_received(frame)
        assert any(
            call[0][0][3:4] == FrameType.GOAWAY.to_bytes(1, "big")
            for call in transport.write.call_args_list
        )

    @pytest.mark.asyncio
    async def test_receive_ping_ack(self, connection):
        """Receiving a PING ACK is logged and does not cause another response."""
        conn, _ = connection
        frame = build_ping(ack=True, opaque=b"12345678")
        conn.data_received(frame)  # no crash, no additional PING sent

    @pytest.mark.asyncio
    async def test_goaway_when_future_already_done(self, connection):
        """GOAWAY should not fail when a stream's future is already complete."""
        conn, _ = connection
        s1 = await conn.create_stream()
        s3 = await conn.create_stream()
        s1.state = s3.state = StreamState.OPEN
        s1.response_future.set_result((s1.stream_id, [], b""))
        frame = build_goaway(last_stream_id=1, error_code=0)
        conn.data_received(frame)
        assert s1.stream_id in conn.streams
        assert s3.stream_id not in conn.streams

    @pytest.mark.asyncio
    async def test_window_update_for_unknown_stream(self, connection):
        """WINDOW_UPDATE on unknown stream must be ignored (no crash)."""
        conn, _ = connection
        frame = build_window_update(123, 100)
        conn.data_received(frame)
        assert conn.session_outbound_window == 65535  # unchanged

    @pytest.mark.asyncio
    async def test_continuation_frame_ignored(self, connection):
        """CONTINUATION frame is ignored with a warning."""
        conn, _ = connection
        frame = frame_header(0, FrameType.CONTINUATION, 0, 1)
        conn.data_received(frame)  # no crash

    @pytest.mark.asyncio
    async def test_unknown_frame_type_ignored(self, connection):
        """Unknown frame type (>9) is ignored."""
        conn, _ = connection
        frame = frame_header(0, 0x1A, 0, 0)
        conn.data_received(frame)  # no crash

    @pytest.mark.asyncio
    async def test_send_data_end_stream_last_chunk(self, connection, mock_transport):
        """send_data with end_stream=True sets END_STREAM on the last chunk."""
        conn, transport = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        conn.session_outbound_window = 100
        stream.outbound_window = 100
        await conn.send_data(stream, b"x" * 10, end_stream=True)
        data_frames = [
            call[0][0]
            for call in transport.write.call_args_list
            if FrameType.DATA.to_bytes(1, "big") in call[0][0]
        ]
        assert len(data_frames) == 1
        assert data_frames[0][4] & FlagData.END_STREAM

    @pytest.mark.asyncio
    async def test_send_request_with_body(self, connection, mock_transport):
        """send_request with body sends HEADERS (no END_STREAM) followed by DATA."""
        conn, transport = connection
        stream = await conn.create_stream()
        await conn.send_request(stream, "POST", url_mock("/"), [], body=b"hello")
        sent = [
            FrameType(call[0][0][3]).name
            for call in transport.write.call_args_list
            if call[0][0][3] in (FrameType.HEADERS, FrameType.DATA)
        ]
        assert sent == ["HEADERS", "DATA"]

    @pytest.mark.asyncio
    async def test_create_stream_after_goaway(self, connection):
        """create_stream raises ConnectionError when GOAWAY has been sent."""
        conn, _ = connection
        conn._goaway_sent = True
        with pytest.raises(ConnectionError):
            await conn.create_stream()

    @pytest.mark.asyncio
    async def test_maybe_unblock_streams_done_future(self, connection):
        """_maybe_unblock_streams skips futures that are already done."""
        conn, _ = connection
        fut = conn._loop.create_future()
        fut.set_result(None)
        conn._pending_streams.append(fut)
        conn._maybe_unblock_streams()
        assert len(conn.streams) == 0  # no new stream created

    @pytest.mark.asyncio
    async def test_connection_lost_done_futures(self, connection):
        """connection_lost must handle streams whose futures are already done."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.response_future.set_result((stream.stream_id, [], b""))
        conn.connection_lost(None)  # no exception


# ----------------------------------------------------------------------
# 2. Miscellaneous tests (race conditions, deadlocks, edge cases)
# ----------------------------------------------------------------------
class TestMiscellaneous:
    @pytest.mark.asyncio
    async def test_concurrent_send_data_does_not_deadlock(
        self, connection, mock_transport
    ):
        """Multiple tasks sending data on the same stream should not deadlock."""
        conn, transport = connection
        stream = await conn.create_stream()
        # Set window large enough
        conn.session_outbound_window = 1_000_000
        stream.outbound_window = 1_000_000

        async def send_chunk():
            await conn.send_data(stream, b"x" * 100, end_stream=False)

        tasks = [asyncio.create_task(send_chunk()) for _ in range(5)]
        await asyncio.gather(*tasks, return_exceptions=True)
        # All writes should complete eventually
        assert transport.write.call_count >= 5

    @pytest.mark.asyncio
    async def test_window_update_wakes_all_waiters(self, connection, mock_transport):
        """When window is zero, multiple blocked tasks resume on WINDOW_UPDATE."""
        conn, transport = connection
        stream = await conn.create_stream()
        conn.session_outbound_window = 0
        stream.outbound_window = 0

        async def blocked_send():
            await conn.send_data(stream, b"hello", end_stream=False)

        task1 = asyncio.create_task(blocked_send())
        task2 = asyncio.create_task(blocked_send())
        await asyncio.sleep(0.01)  # both waiting

        # Simulate WINDOW_UPDATE that opens 10 bytes
        frame = build_window_update(0, 10)  # session
        conn.data_received(frame)
        frame2 = build_window_update(stream.stream_id, 10)
        conn.data_received(frame2)
        await asyncio.sleep(0.01)
        assert task1.done()
        assert task2.done()

    @pytest.mark.asyncio
    async def test_stream_cancelled_before_response(self, connection):
        """Pending create_stream futures are cancelled on connection loss."""
        conn, _ = connection
        conn.max_concurrent_streams = 1
        await conn.create_stream()
        # Queue a second stream
        fut = asyncio.ensure_future(conn.create_stream())
        await asyncio.sleep(0.01)
        assert not fut.done()
        # Simulate connection loss
        conn.connection_lost(ConnectionError("test"))
        await asyncio.sleep(0.01)
        assert fut.done()
        with pytest.raises(ConnectionError):
            fut.result()

    @pytest.mark.asyncio
    async def test_close_stream_on_rst_without_headers(self, connection):
        """RST_STREAM before headers deliver must resolve future with error."""
        conn, _ = connection
        stream = await conn.create_stream()
        frame = build_rst_stream(stream.stream_id, error_code=0x8)
        conn.data_received(frame)
        assert stream.response_future.done()
        with pytest.raises(RuntimeError):
            stream.response_future.result()

    @pytest.mark.asyncio
    async def test_data_received_without_connection(self, protocol):
        """Http2Protocol.data_received is a no‑op before connection_made."""
        proto, _ = protocol
        proto._connection = None
        proto.data_received(b"anything")  # must not raise


# ----------------------------------------------------------------------
# 3. Interface tests (high‑level features via Http2Protocol.send)
# ----------------------------------------------------------------------
class TestHighLevelInterface:
    @pytest.mark.asyncio
    async def test_json_response(self, protocol, mock_transport):
        """send() returns a Http2Response with correct JSON body."""
        proto, transport = protocol

        # Start a request using the public API
        async def do_request():
            # url_mock() returns a simple URL object with required attributes
            return await proto.send(
                "GET", url_mock("/json"), headers=[("accept", "application/json")]
            )

        task = asyncio.create_task(do_request())
        # Let it run until it creates a stream and sends HEADERS
        await asyncio.sleep(0.01)
        headers = [(":status", "200"), ("content-type", "application/json")]
        body = b'{"key": "value"}'
        resp_frame = build_headers_frame(
            1, headers, end_stream=False
        ) + build_data_frame(1, body, end_stream=True)
        proto.data_received(resp_frame)
        response = await task
        assert response.status == 200
        assert response.body == body
        assert json.loads(response.body) == {"key": "value"}

    @pytest.mark.asyncio
    async def test_redirect_response(self, protocol, mock_transport):
        """302 redirect headers are correctly returned."""
        proto, transport = protocol
        task = asyncio.create_task(proto.send("GET", url_mock("/redirect"), headers=[]))
        await asyncio.sleep(0.01)
        headers = [(":status", "302"), ("location", "/new")]
        resp_frame = build_headers_frame(1, headers, end_stream=True)
        proto.data_received(resp_frame)
        resp = await task
        assert resp.status == 302
        assert dict(resp.headers).get("location") == "/new"

    @pytest.mark.asyncio
    async def test_compressed_body_delivery(self, protocol, mock_transport):
        """Response with content-encoding: gzip delivers raw compressed bytes."""
        proto, transport = protocol
        task = asyncio.create_task(proto.send("GET", url_mock("/gzip"), headers=[]))
        await asyncio.sleep(0.01)
        raw_data = gzip.compress(b"uncompressed")
        headers = [(":status", "200"), ("content-encoding", "gzip")]
        frames = build_headers_frame(1, headers, end_stream=False) + build_data_frame(
            1, raw_data, end_stream=True
        )
        proto.data_received(frames)
        resp = await task
        assert resp.body == raw_data
        # Higher layer (aiohttp) will handle decompression

    async def test_multiple_requests_concurrently(self, protocol, mock_transport):
        """Multiple send() calls create distinct streams and receive responses."""
        proto, transport = protocol
        tasks = []
        for i in range(2):
            tasks.append(asyncio.create_task(proto.send("GET", url_mock(f"/r{i}"), [])))
        await asyncio.sleep(0.01)

        # Stream 1 and 3 should have been created
        # Respond to each
        resp1 = build_headers_frame(1, [(":status", "200")], end_stream=True)
        resp3 = build_headers_frame(3, [(":status", "201")], end_stream=True)
        proto.data_received(resp1)
        proto.data_received(resp3)

        r1, r2 = await asyncio.gather(*tasks)
        assert r1.status == 200
        assert r2.status == 201

    @pytest.mark.asyncio
    async def test_response_all_methods(self):
        """Cover Http2Response.read, .text, .json, .cookies, .raise_for_status, .release, .close, context manager."""
        headers = [
            (":status", "200"),
            ("set-cookie", "a=b"),
            ("content-type", "application/json"),
        ]
        body = b'{"ok":true}'
        resp = Http2Response(headers, body, method="GET", url=url_mock("/"))
        assert resp.status == 200
        assert await resp.read() == body
        assert await resp.text() == '{"ok":true}'
        assert await resp.json() == {"ok": True}
        assert "a" in resp.cookies
        resp.raise_for_status()  # 200 is ok
        resp.release()
        resp.close()
        async with resp:
            pass

    @pytest.mark.asyncio
    async def test_response_raise_for_status_error(self):
        """Http2Response.raise_for_status raises for 4xx."""
        headers = [(":status", "404")]
        resp = Http2Response(headers, b"", method="GET", url=url_mock("/"))
        from aiohttp.client_exceptions import ClientResponseError

        with pytest.raises(ClientResponseError):
            resp.raise_for_status()

    @pytest.mark.asyncio
    async def test_send_with_body_through_protocol(self, protocol, mock_transport):
        """Full send() with a body completes successfully."""
        proto, transport = protocol
        url = url_mock("/upload")
        task = asyncio.create_task(proto.send("POST", url, [], body=b"data"))
        await asyncio.sleep(0.01)
        resp_frame = build_headers_frame(1, [(":status", "200")], end_stream=True)
        proto.data_received(resp_frame)
        response = await task
        assert response.status == 200


class TestStreamStateMachine:
    @pytest.mark.asyncio
    async def test_invalid_transition_raises(self, connection):
        """Invalid state transition raises ProtocolError."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        with pytest.raises(ProtocolError):
            stream.transition(StreamState.RESERVED_LOCAL)

    @pytest.mark.asyncio
    async def test_receive_data_end_stream_half_closed_local(self, connection):
        """DATA END_STREAM when HALF_CLOSED_LOCAL -> CLOSED and stream removed."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.HALF_CLOSED_LOCAL
        stream.response_headers = [(":status", "200")]
        stream.receive_data(b"body", end_stream=True)
        assert stream.state == StreamState.CLOSED
        assert stream.stream_id not in conn.streams

    @pytest.mark.asyncio
    async def test_receive_data_end_stream_invalid_state(self, connection):
        """DATA END_STREAM in CLOSED state raises ProtocolError."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.CLOSED
        with pytest.raises(ProtocolError):
            stream.receive_data(b"x", end_stream=True)

    @pytest.mark.asyncio
    async def test_receive_headers_end_stream_half_closed_local(self, connection):
        """HEADERS END_STREAM when HALF_CLOSED_LOCAL -> CLOSED and stream removed."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.HALF_CLOSED_LOCAL
        stream.receive_headers([(":status", "200")], end_stream=True)
        assert stream.state == StreamState.CLOSED
        assert stream.stream_id not in conn.streams

    @pytest.mark.asyncio
    async def test_receive_headers_end_stream_invalid_state(self, connection):
        """HEADERS END_STREAM in CLOSED state raises ProtocolError."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.CLOSED
        with pytest.raises(ProtocolError):
            stream.receive_headers([(":status", "200")], end_stream=True)

    @pytest.mark.asyncio
    async def test_data_stream_before_headers(self, connection):
        """DATA before headers does NOT set future until headers arrive."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        # double end stream is invalid
        stream.receive_data(b"body", end_stream=False)
        assert not stream.response_future.done()
        stream.receive_headers([(":status", "200")], end_stream=True)
        assert stream.response_future.done()
        _, headers, body = stream.response_future.result()
        assert body == b"body"

    @pytest.mark.asyncio
    async def test_future_already_done_data_end_stream(self, connection):
        """receive_data with END_STREAM does not double‑set an already done future."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        stream.response_headers = [(":status", "200")]
        stream.response_future.set_result(
            (stream.stream_id, stream.response_headers, b"")
        )
        stream.receive_data(b"more", end_stream=True)  # no exception

    @pytest.mark.asyncio
    async def test_future_already_done_headers_end_stream(self, connection):
        """receive_headers with END_STREAM does not double‑set an already done future."""
        conn, _ = connection
        stream = await conn.create_stream()
        stream.state = StreamState.OPEN
        stream.response_future.set_result((stream.stream_id, [], b""))
        stream.receive_headers([(":status", "200")], end_stream=True)  # no exception
