"""
Fuzzy tests for HTTP/2.
These aim to test a sample of the cartesian product of all possible HTTP/2 messages.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from http2.fuzz import FuzzerConfig, Http2ServerFuzzer

from aiohttp.http2.connection import Http2Connection, Http2Protocol


async def test_fuzz_client(
    connection: Any, mock_transport: Any, event_loop: Any
) -> None:
    # connection fixture returns (Http2Connection, mock_transport)
    conn, transport = connection
    config = FuzzerConfig(seed=42, max_frames_per_cycle=3)
    fuzzer = Http2ServerFuzzer(conn, transport, config, max_cycles=50)
    bugs = fuzzer.run()
    assert not bugs, f"Bugs found: {bugs}"
