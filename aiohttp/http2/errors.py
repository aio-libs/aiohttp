class ProtocolError(Exception):
    pass


# (rfc7540/rfc9113, Section 7)
class ErrorCode:
    NO_ERROR = 0
    PROTOCOL_ERROR = 1
    INTERNAL_ERROR = 2
    FLOW_CONTROL_ERROR = 3
    CANCEL = 8
