"""WebSocket models for protocol versions 13 and 8."""

import sys
from enum import IntEnum
from struct import Struct
from typing import Final, Set, cast

__all__ = (
    "WS_KEY",
    "WebSocketError",
    "WSMsgType",
    "WSCloseCode",
)


class WSCloseCode(IntEnum):
    OK = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    ABNORMAL_CLOSURE = 1006
    INVALID_TEXT = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014


ALLOWED_CLOSE_CODES: Final[Set[int]] = {int(i) for i in WSCloseCode}

# For websockets, keeping latency low is extremely important as implementations
# generally expect to be able to send and receive messages quickly.  We use a
# larger chunk size than the default to reduce the number of executor calls
# since the executor is a significant source of latency and overhead when
# the chunks are small. A size of 5KiB was chosen because it is also the
# same value python-zlib-ng choose to use as the threshold to release the GIL.

WEBSOCKET_MAX_SYNC_CHUNK_SIZE = 5 * 1024


class WSMsgType(IntEnum):
    # websocket spec types
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    PING = 0x9
    PONG = 0xA
    CLOSE = 0x8

    # aiohttp specific types
    CLOSING = 0x100
    CLOSED = 0x101
    ERROR = 0x102


MESSAGE_TYPES_WITH_CONTENT: Final = frozenset(
    {
        WSMsgType.BINARY,
        WSMsgType.TEXT,
        WSMsgType.CONTINUATION,
    }
)

WS_KEY: Final[bytes] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


UNPACK_LEN2 = Struct("!H").unpack_from
UNPACK_LEN3 = Struct("!Q").unpack_from
UNPACK_CLOSE_CODE = Struct("!H").unpack
PACK_LEN1 = Struct("!BB").pack
PACK_LEN2 = Struct("!BBH").pack
PACK_LEN3 = Struct("!BBQ").pack
PACK_CLOSE_CODE = Struct("!H").pack
PACK_RANDBITS = Struct("!L").pack
MSG_SIZE: Final[int] = 2**14
DEFAULT_LIMIT: Final[int] = 2**16
MASK_LEN: Final[int] = 4


class WebSocketError(Exception):
    """WebSocket protocol parser error."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(code, message)

    def __str__(self) -> str:
        return cast(str, self.args[1])


class WSHandshakeError(Exception):
    """WebSocket protocol handshake error."""


native_byteorder: Final[str] = sys.byteorder


class WSParserState(IntEnum):
    READ_HEADER = 1
    READ_PAYLOAD_LENGTH = 2
    READ_PAYLOAD_MASK = 3
    READ_PAYLOAD = 4
