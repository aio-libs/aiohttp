import http.server
import sys
from typing import Mapping, Tuple

from . import __version__
from .http_exceptions import HttpProcessingError as HttpProcessingError
from .http_parser import (
    HeadersParser as HeadersParser,
    HttpParser as HttpParser,
    HttpRequestParser as HttpRequestParser,
    HttpResponseParser as HttpResponseParser,
    RawRequestMessage as RawRequestMessage,
    RawResponseMessage as RawResponseMessage,
)
from .http_websocket import (
    WS_CLOSED_MESSAGE as WS_CLOSED_MESSAGE,
    WS_CLOSING_MESSAGE as WS_CLOSING_MESSAGE,
    WS_KEY as WS_KEY,
    WebSocketError as WebSocketError,
    WebSocketReader as WebSocketReader,
    WebSocketWriter as WebSocketWriter,
    WSCloseCode as WSCloseCode,
    WSMessage as WSMessage,
    WSMsgType as WSMsgType,
    ws_ext_gen as ws_ext_gen,
    ws_ext_parse as ws_ext_parse,
)
from .http_writer import (
    HttpVersion as HttpVersion,
    HttpVersion10 as HttpVersion10,
    HttpVersion11 as HttpVersion11,
    StreamWriter as StreamWriter,
)

__all__ = (
    "HeadersParser",
    "HttpParser",
    "HttpProcessingError",
    "HttpRequestParser",
    "HttpResponseParser",
    "HttpVersion",
    "HttpVersion10",
    "HttpVersion11",
    "RESPONSES",
    "RawRequestMessage",
    "RawResponseMessage",
    "SERVER_SOFTWARE",
    "StreamWriter",
    "WSCloseCode",
    "WSMessage",
    "WSMsgType",
    "WS_CLOSED_MESSAGE",
    "WS_CLOSING_MESSAGE",
    "WS_KEY",
    "WebSocketError",
    "WebSocketReader",
    "WebSocketWriter",
    "ws_ext_gen",
    "ws_ext_parse",
)


SERVER_SOFTWARE = "Python/{0[0]}.{0[1]} aiohttp/{1}".format(
    sys.version_info, __version__
)  # type: str

RESPONSES = (
    http.server.BaseHTTPRequestHandler.responses
)  # type: Mapping[int, Tuple[str, str]]
