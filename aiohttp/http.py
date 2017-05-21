import http.server
import sys

from yarl import URL  # noqa

from . import __version__
from .http_exceptions import HttpProcessingError
from .http_parser import (HttpParser, HttpRequestParser, HttpResponseParser,
                          RawRequestMessage, RawResponseMessage)
from .http_websocket import (WS_CLOSED_MESSAGE, WS_CLOSING_MESSAGE, WS_KEY,
                             WebSocketError, WebSocketReader, WebSocketWriter,
                             WSCloseCode, WSMessage, WSMsgType, do_handshake)
from .http_writer import (HttpVersion, HttpVersion10, HttpVersion11,
                          PayloadWriter, StreamWriter)


__all__ = (
    'HttpProcessingError', 'RESPONSES', 'SERVER_SOFTWARE',

    # .http_writer
    'PayloadWriter', 'HttpVersion', 'HttpVersion10', 'HttpVersion11',
    'StreamWriter',

    # .http_parser
    'HttpParser', 'HttpRequestParser', 'HttpResponseParser',
    'RawRequestMessage', 'RawResponseMessage',

    # .http_websocket
    'WS_CLOSED_MESSAGE', 'WS_CLOSING_MESSAGE', 'WS_KEY',
    'WebSocketReader', 'WebSocketWriter', 'do_handshake',
    'WSMessage', 'WebSocketError', 'WSMsgType', 'WSCloseCode',
)


SERVER_SOFTWARE = 'Python/{0[0]}.{0[1]} aiohttp/{1}'.format(
    sys.version_info, __version__)

RESPONSES = http.server.BaseHTTPRequestHandler.responses
