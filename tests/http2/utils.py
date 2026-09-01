import asyncio
import struct
from typing import Any, Generator, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
from hpack import Encoder

from aiohttp.http2.connection import Http2Protocol, Http2Connection
from aiohttp.http2.settings import (
    FrameType,
    FlagSettings,
    FlagHeaders,
    FlagData,
    FlagPing,
    Setting,
)

import asyncio
from typing import Any, Generator
from unittest.mock import MagicMock


# ----------------------------------------------------------------------
# Helper: minimal URL mock
# ----------------------------------------------------------------------
def url_mock(path: str = "/") -> Any:
    """Create a simple URL-like object expected by the implementation."""
    return type(
        "URL",
        (),
        {"scheme": "https", "host": "example.com", "path": path, "query": None},
    )

# ----------------------------------------------------------------------
# Frame construction helpers
# ----------------------------------------------------------------------
def frame_header(length: int, ftype: int, flags: int, stream_id: int) -> bytes:
    # 24-bit length (3 bytes) + type + flags + stream_id
    return struct.pack("!I", length)[1:] + struct.pack(
        "!B B I", ftype, flags, stream_id
    )


def build_settings_frame(
    settings_pairs: Optional[list[tuple[Setting, int]]] = None, ack: bool = False
) -> bytes:
    payload = b""
    if not ack and settings_pairs:
        for setting_id, value in settings_pairs:
            payload += struct.pack("!H I", setting_id, value)
    flags = FlagSettings.ACK if ack else 0
    return frame_header(len(payload), FrameType.SETTINGS, flags, 0) + payload


def build_headers_frame(
    stream_id: int,
    headers: list[tuple[str, str]],
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
