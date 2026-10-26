"""Helpers for WebSocket protocol versions 13 and 8."""

import functools
import re
from re import Pattern
from struct import Struct
from typing import TYPE_CHECKING, Final

from ..helpers import NO_EXTENSIONS
from .models import WSCloseCode, WSHandshakeError

UNPACK_LEN3 = Struct("!Q").unpack_from
UNPACK_CLOSE_CODE = Struct("!H").unpack
PACK_LEN1 = Struct("!BB").pack
PACK_LEN2 = Struct("!BBH").pack
PACK_LEN3 = Struct("!BBQ").pack
PACK_CLOSE_CODE = Struct("!H").pack
PACK_RANDBITS = Struct("!L").pack
MSG_SIZE: Final[int] = 2**14
MASK_LEN: Final[int] = 4

WS_KEY: Final[bytes] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# https://datatracker.ietf.org/doc/html/rfc6455#section-5.5
MAX_CONTROL_FRAME_PAYLOAD: Final[int] = 125

# Close codes a peer accepts on the wire.  This mirrors ALLOWED_CLOSE_CODES in
# reader_py.py, which cannot be reused here because the compiled reader
# declares it as a cdef set: ABNORMAL_CLOSURE is generated locally and must
# never be sent, and RFC 6455 reserves everything outside 1000-4999.
SENDABLE_CLOSE_CODES: Final[frozenset[int]] = frozenset(
    int(code) for code in WSCloseCode if code is not WSCloseCode.ABNORMAL_CLOSURE
)


def validate_close_code(code: int) -> None:
    """Validate a close status code as required by RFC 6455 section 7.4."""
    if not 0 <= code <= 65535:
        raise ValueError(f"Invalid close code: {code}")
    if code > 4999 or (code < 3000 and code not in SENDABLE_CLOSE_CODES):
        raise ValueError(f"Invalid close code: {code}")


def validate_close_payload(payload: bytes) -> None:
    """Validate the payload of a Close frame before it is written.

    A peer applies the checks from RFC 6455 sections 5.5 and 7.4 that our own
    reader applies, so an invalid Close frame only gets the connection torn
    down with 1002 instead of closing it cleanly.
    """
    if len(payload) > MAX_CONTROL_FRAME_PAYLOAD:
        raise ValueError(
            "Control frame payload cannot be larger than "
            f"{MAX_CONTROL_FRAME_PAYLOAD} bytes"
        )
    if not payload:
        # A Close frame without a body is valid and carries no status code.
        return
    if len(payload) < 2:
        raise ValueError("Close frame payload must be empty or at least 2 bytes")
    validate_close_code(UNPACK_CLOSE_CODE(payload[:2])[0])
    try:
        payload[2:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Close reason must be valid UTF-8") from exc


def validate_close_frame(code: int, message: bytes | str = b"") -> bytes:
    """Validate a Close frame given its status code and reason."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    validate_close_code(code)
    validate_close_payload(PACK_CLOSE_CODE(code) + message)
    return message


# Used by _websocket_mask_python
@functools.lru_cache
def _xor_table() -> list[bytes]:
    return [bytes(a ^ b for a in range(256)) for b in range(256)]


def _websocket_mask_python(mask: bytes, data: bytearray) -> None:
    """Websocket masking function.

    `mask` is a `bytes` object of length 4; `data` is a `bytearray`
    object of any length. The contents of `data` are masked with `mask`,
    as specified in section 5.3 of RFC 6455.

    Note that this function mutates the `data` argument.

    This pure-python implementation may be replaced by an optimized
    version when available.

    """
    assert isinstance(data, bytearray), data
    assert len(mask) == 4, mask

    if data:
        _XOR_TABLE = _xor_table()
        a, b, c, d = (_XOR_TABLE[n] for n in mask)
        data[::4] = data[::4].translate(a)
        data[1::4] = data[1::4].translate(b)
        data[2::4] = data[2::4].translate(c)
        data[3::4] = data[3::4].translate(d)


if TYPE_CHECKING or NO_EXTENSIONS:
    websocket_mask = _websocket_mask_python
else:
    try:
        from .mask import _websocket_mask_cython  # type: ignore[import-not-found]

        websocket_mask = _websocket_mask_cython
    except ImportError:  # pragma: no cover
        websocket_mask = _websocket_mask_python


_WS_EXT_RE: Final[Pattern[str]] = re.compile(
    r"^(?:;\s*(?:"
    r"(server_no_context_takeover)|"
    r"(client_no_context_takeover)|"
    r"(server_max_window_bits(?:=(\d+))?)|"
    r"(client_max_window_bits(?:=(\d+))?)))*$"
)

_WS_EXT_RE_SPLIT: Final[Pattern[str]] = re.compile(r"permessage-deflate([^,]+)?")


def ws_ext_parse(extstr: str | None, isserver: bool = False) -> tuple[int, bool]:
    if not extstr:
        return 0, False

    compress = 0
    notakeover = False
    for ext in _WS_EXT_RE_SPLIT.finditer(extstr):
        defext = ext.group(1)
        # Return compress = 15 when get `permessage-deflate`
        if not defext:
            compress = 15
            break
        match = _WS_EXT_RE.match(defext)
        if match:
            compress = 15
            if isserver:
                # Server never fail to detect compress handshake.
                # Server does not need to send max wbit to client
                if match.group(4):
                    compress = int(match.group(4))
                    # Group3 must match if group4 matches
                    # Compress wbit 8 does not support in zlib
                    # If compress level not support,
                    # CONTINUE to next extension
                    if compress > 15 or compress < 9:
                        compress = 0
                        continue
                if match.group(1):
                    notakeover = True
                # Ignore regex group 5 & 6 for client_max_window_bits
                break
            else:
                if match.group(6):
                    compress = int(match.group(6))
                    # Group5 must match if group6 matches
                    # Compress wbit 8 does not support in zlib
                    # If compress level not support,
                    # FAIL the parse progress
                    if compress > 15 or compress < 9:
                        raise WSHandshakeError("Invalid window size")
                if match.group(2):
                    notakeover = True
                # Ignore regex group 5 & 6 for client_max_window_bits
                break
        # Return Fail if client side and not match
        elif not isserver:
            raise WSHandshakeError("Extension for deflate not supported" + ext.group(1))

    return compress, notakeover


def ws_ext_gen(
    compress: int = 15, isserver: bool = False, server_notakeover: bool = False
) -> str:
    # client_notakeover=False not used for server
    # compress wbit 8 does not support in zlib
    if compress < 9 or compress > 15:
        raise ValueError(
            "Compress wbits must between 9 and 15, zlib does not support wbits=8"
        )
    enabledext = ["permessage-deflate"]
    if not isserver:
        enabledext.append("client_max_window_bits")

    if compress < 15:
        enabledext.append("server_max_window_bits=" + str(compress))
    if server_notakeover:
        enabledext.append("server_no_context_takeover")
    # if client_notakeover:
    #     enabledext.append('client_no_context_takeover')
    return "; ".join(enabledext)
