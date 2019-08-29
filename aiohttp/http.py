import http.server
import sys
from typing import Mapping, Tuple  # noqa

from . import __version__
from .http_exceptions import HttpProcessingError as HttpProcessingError
from .http_parser import HeadersParser as HeadersParser
from .http_parser import HttpParser as HttpParser
from .http_parser import HttpRequestParser as HttpRequestParser
from .http_parser import HttpResponseParser as HttpResponseParser
from .http_parser import RawRequestMessage as RawRequestMessage
from .http_parser import RawResponseMessage as RawResponseMessage
from .http_websocket import WS_CLOSED_MESSAGE as WS_CLOSED_MESSAGE
from .http_websocket import WS_CLOSING_MESSAGE as WS_CLOSING_MESSAGE
from .http_websocket import WS_KEY as WS_KEY
from .http_websocket import WebSocketError as WebSocketError
from .http_websocket import WebSocketReader as WebSocketReader
from .http_websocket import WebSocketWriter as WebSocketWriter
from .http_websocket import WSCloseCode as WSCloseCode
from .http_websocket import WSMessage as WSMessage
from .http_websocket import WSMsgType as WSMsgType
from .http_websocket import ws_ext_gen as ws_ext_gen
from .http_websocket import ws_ext_parse as ws_ext_parse
from .http_writer import HttpVersion as HttpVersion
from .http_writer import HttpVersion10 as HttpVersion10
from .http_writer import HttpVersion11 as HttpVersion11
from .http_writer import StreamWriter as StreamWriter

__all__ = (
    'HttpProcessingError', 'RESPONSES', 'SERVER_SOFTWARE',

    # .http_writer
    'StreamWriter', 'HttpVersion', 'HttpVersion10', 'HttpVersion11',

    # .http_parser
    'HeadersParser', 'HttpParser',
    'HttpRequestParser', 'HttpResponseParser',
    'RawRequestMessage', 'RawResponseMessage',

    # .http_websocket
    'WS_CLOSED_MESSAGE', 'WS_CLOSING_MESSAGE', 'WS_KEY',
    'WebSocketReader', 'WebSocketWriter', 'ws_ext_gen', 'ws_ext_parse',
    'WSMessage', 'WebSocketError', 'WSMsgType', 'WSCloseCode',
)


SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
    sys.version_info, __version__)  # type: str

RESPONSES = http.server.BaseHTTPRequestHandler.responses  # type: Mapping[int, Tuple[str, str]]  # noqa
