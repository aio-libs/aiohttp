"""Fuzzy tests for HTTP/2. These aim to test a sample of the cartesian product of all possible HTTP/2 messages."""

from typing import Any
from unittest.mock import MagicMock

from http2.fuzz import FuzzerConfig, Http2ServerFuzzer  # noqa: I900

async def test_fuzz_client(
    connection: Any, mock_transport: Any, event_loop: Any
) -> None:
    conn, transport = connection
    config = FuzzerConfig(seed=42, max_frames_per_cycle=3)
    fuzzer = Http2ServerFuzzer(conn, transport, config, max_cycles=50)
    bugs = fuzzer.run()
    assert not bugs, f"Bugs found: {bugs}"
