from enum import IntEnum


class ProtocolError(Exception):
    pass


# (rfc7540/rfc9113, Section 7)
class ErrorCode(IntEnum):
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    CANCEL = 0x8
