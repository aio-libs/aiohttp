import time

import pytest

from aiohttp._websocket.helpers import ws_ext_parse
from aiohttp.http_websocket import WSHandshakeError


class TestWsExtParse:
    def test_empty(self) -> None:
        assert ws_ext_parse(None) == (0, False)
        assert ws_ext_parse("") == (0, False)

    def test_permessage_deflate_only(self) -> None:
        compress, notakeover = ws_ext_parse("permessage-deflate")
        assert compress == 15
        assert notakeover is False

    def test_server_no_context_takeover(self) -> None:
        compress, notakeover = ws_ext_parse(
            "permessage-deflate; server_no_context_takeover", isserver=True
        )
        assert compress == 15
        assert notakeover is True

    def test_client_no_context_takeover(self) -> None:
        compress, notakeover = ws_ext_parse(
            "permessage-deflate; client_no_context_takeover", isserver=False
        )
        assert compress == 15
        assert notakeover is True

    def test_server_max_window_bits(self) -> None:
        compress, notakeover = ws_ext_parse(
            "permessage-deflate; server_max_window_bits=12", isserver=True
        )
        assert compress == 12
        assert notakeover is False

    def test_client_max_window_bits(self) -> None:
        compress, notakeover = ws_ext_parse(
            "permessage-deflate; client_max_window_bits=10", isserver=False
        )
        assert compress == 10
        assert notakeover is False

    def test_window_bits_out_of_range_server(self) -> None:
        # out-of-range wbits on server side → skip, return 0
        compress, _ = ws_ext_parse(
            "permessage-deflate; server_max_window_bits=8", isserver=True
        )
        assert compress == 0

    def test_window_bits_out_of_range_client(self) -> None:
        with pytest.raises(WSHandshakeError):
            ws_ext_parse("permessage-deflate; client_max_window_bits=8", isserver=False)

    def test_invalid_extension_client_raises(self) -> None:
        with pytest.raises(WSHandshakeError):
            ws_ext_parse("permessage-deflate; unknown_param", isserver=False)

    def test_no_match_server_returns_zero(self) -> None:
        compress, notakeover = ws_ext_parse(
            "permessage-deflate; unknown_param", isserver=True
        )
        assert compress == 0
        assert notakeover is False

    def test_backtracking_performance(self) -> None:
        # Crafted input: many valid tokens followed by an invalid suffix.
        # Without the atomic group fix this causes exponential backtracking.
        evil = "permessage-deflate" + ("; server_no_context_takeover" * 30) + ";INVALID"
        start = time.perf_counter()
        try:
            ws_ext_parse(evil, isserver=True)
        except WSHandshakeError:
            pass
        elapsed = time.perf_counter() - start
        # Should complete in well under a second on any reasonable hardware.
        assert elapsed < 1.0, f"possible backtracking regression: took {elapsed:.3f}s"
