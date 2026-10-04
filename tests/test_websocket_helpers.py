import time

import pytest

from aiohttp._websocket.helpers import ws_ext_parse
from aiohttp.http_websocket import WSHandshakeError


@pytest.mark.parametrize(
    ("msg", "server", "expected"),
    (
        ("permessage-deflate", False, (15, False)),
        ("permessage-deflate; server_no_context_takeover", True, (15, True)),
        ("permessage-deflate; client_no_context_takeover", False, (15, True)),
        ("permessage-deflate; server_max_window_bits=12", True, (12, False)),
        ("permessage-deflate; client_max_window_bits=10", False, (10, False)),
        # out-of-range wbits on server side → skip rather than fail
        ("permessage-deflate; server_max_window_bits=8", True, (0, False)),
        # unknown param on server side → no match, return zero
        ("permessage-deflate; unknown_param", True, (0, False)),
    ),
)
def test_ws_ext_parse(msg: str, server: bool, expected: tuple[int, bool]) -> None:
    assert ws_ext_parse(msg, isserver=server) == expected


@pytest.mark.parametrize(
    ("msg", "server"),
    (
        ("permessage-deflate; client_max_window_bits=8", False),
        ("permessage-deflate; unknown_param", False),
    ),
)
def test_ws_ext_parse_raises(msg: str, server: bool) -> None:
    with pytest.raises(WSHandshakeError):
        ws_ext_parse(msg, isserver=server)


def test_ws_ext_parse_empty() -> None:
    assert ws_ext_parse(None) == (0, False)
    assert ws_ext_parse("") == (0, False)


def test_ws_ext_parse_backtracking_performance() -> None:
    # Many valid tokens followed by an invalid suffix — the classic input that
    # triggers exponential backtracking in the outer repeating group.
    evil = "permessage-deflate" + ("; server_no_context_takeover" * 30) + ";INVALID"
    start = time.perf_counter()
    with pytest.raises(WSHandshakeError):
        ws_ext_parse(evil, isserver=False)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"backtracking regression: took {elapsed:.3f}s"
