"""WebSocket protocol versions 13 and 8."""

import json
from enum import IntEnum
from typing import Any, Callable, Final, Literal, NamedTuple, Optional, Union, cast

WS_DEFLATE_TRAILING: Final[bytes] = bytes([0x00, 0x00, 0xFF, 0xFF])


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


class WSMessageContinuation(NamedTuple):
    data: bytes
    extra: Optional[str] = None
    type: Literal[WSMsgType.CONTINUATION] = WSMsgType.CONTINUATION


class WSMessageText(NamedTuple):
    data: str
    extra: Optional[str] = None
    type: Literal[WSMsgType.TEXT] = WSMsgType.TEXT

    def json(
        self, *, loads: Callable[[Union[str, bytes, bytearray]], Any] = json.loads
    ) -> Any:
        """Return parsed JSON data."""
        return loads(self.data)


class WSMessageBinary(NamedTuple):
    data: bytes
    extra: Optional[str] = None
    type: Literal[WSMsgType.BINARY] = WSMsgType.BINARY

    def json(
        self, *, loads: Callable[[Union[str, bytes, bytearray]], Any] = json.loads
    ) -> Any:
        """Return parsed JSON data."""
        return loads(self.data)


class WSMessagePing(NamedTuple):
    data: bytes
    extra: Optional[str] = None
    type: Literal[WSMsgType.PING] = WSMsgType.PING


class WSMessagePong(NamedTuple):
    data: bytes
    extra: Optional[str] = None
    type: Literal[WSMsgType.PONG] = WSMsgType.PONG


class WSMessageClose(NamedTuple):
    data: int
    extra: Optional[str] = None
    type: Literal[WSMsgType.CLOSE] = WSMsgType.CLOSE


class WSMessageClosing(NamedTuple):
    data: None = None
    extra: Optional[str] = None
    type: Literal[WSMsgType.CLOSING] = WSMsgType.CLOSING


class WSMessageClosed(NamedTuple):
    data: None = None
    extra: Optional[str] = None
    type: Literal[WSMsgType.CLOSED] = WSMsgType.CLOSED


class WSMessageError(NamedTuple):
    data: BaseException
    extra: Optional[str] = None
    type: Literal[WSMsgType.ERROR] = WSMsgType.ERROR


WSMessage = Union[
    WSMessageContinuation,
    WSMessageText,
    WSMessageBinary,
    WSMessagePing,
    WSMessagePong,
    WSMessageClose,
    WSMessageClosing,
    WSMessageClosed,
    WSMessageError,
]

WS_CLOSED_MESSAGE = WSMessageClosed()
WS_CLOSING_MESSAGE = WSMessageClosing()


class WebSocketError(Exception):
    """WebSocket protocol parser error."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(code, message)

    def __str__(self) -> str:
        return cast(str, self.args[1])


class WSHandshakeError(Exception):
    """WebSocket protocol handshake error."""
