from enum import IntEnum, IntFlag
from typing import Dict


# ----------------------------------------------------------------------
# HTTP/2 Frame Definitions (RFC 7540, 4)
# ----------------------------------------------------------------------
class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9


class FlagData(IntFlag):
    END_STREAM = 0x1
    PADDED = 0x8


class FlagHeaders(IntFlag):
    END_STREAM = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY = 0x20


class FlagSettings(IntFlag):
    ACK = 0x1


class FlagPing(IntFlag):
    ACK = 0x1


# Known settings parameters
class Setting(IntEnum):
    HEADER_TABLE_SIZE = 0x1
    ENABLE_PUSH = 0x2
    MAX_CONCURRENT_STREAMS = 0x3
    INITIAL_WINDOW_SIZE = 0x4
    MAX_FRAME_SIZE = 0x5
    MAX_HEADER_LIST_SIZE = 0x6
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8
    NO_RFC7540_PRIORITIES = 0x9


# Default values (RFC 7540, 6.5.2)
DEFAULT_SETTINGS: Dict[Setting, int] = {
    Setting.HEADER_TABLE_SIZE: 4096,
    Setting.ENABLE_PUSH: 1,
    Setting.MAX_CONCURRENT_STREAMS: 2**32 - 1,
    Setting.INITIAL_WINDOW_SIZE: 65535,
    Setting.MAX_FRAME_SIZE: 16384,
    Setting.MAX_HEADER_LIST_SIZE: 2**32 - 1,
}
