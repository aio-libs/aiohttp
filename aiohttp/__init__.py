__version__ = '2.0.0a0'

# This relies on each of the submodules having an __all__ variable.

from . import hdrs  # noqa
from .client import *  # noqa
from .helpers import *  # noqa
from .http_message import HttpVersion, HttpVersion10, HttpVersion11  # noqa
from .http_websocket import WSMsgType, WSCloseCode, WSMessage, WebSocketError  # noqa
from .streams import *  # noqa
from .multipart import *  # noqa
from .file_sender import FileSender  # noqa
from .cookiejar import CookieJar  # noqa
from .resolver import *  # noqa

# deprecated #1657
from .http_message import HttpMessage, Request, Response  # noqa isort:skip
from .http_parser import RawRequestMessage, RawResponseMessage  # noqa isort:skip
from .http_parser import HttpRequestParser, HttpResponseParser, HttpPayloadParser  # noqa isort:skip
from .http_exceptions import HttpProcessingError, BadHttpMessage  # noqa isort:skip
from .http_exceptions import HttpBadRequest, BadStatusLine, LineTooLong, InvalidHeader  # noqa isort:skip
from .client_exceptions import ClientDisconnectedError, ClientTimeoutError, FingerprintMismatch, HttpProxyError, ProxyConnectionError  # noqa isort:skip


__all__ = (client.__all__ +  # noqa
           helpers.__all__ +  # noqa
           streams.__all__ +  # noqa
           multipart.__all__ +  # noqa
           ('hdrs', 'FileSender',
            'HttpVersion', 'HttpVersion10', 'HttpVersion11',
            'WSMsgType', 'MsgType', 'WSCloseCode',
            'WebSocketError', 'WSMessage', 'CookieJar',

            # deprecated api #1657
            'HttpMessage', 'Request', 'Response',
            'HttpRequestParser', 'HttpResponseParser', 'HttpPayloadParser',
            'RawRequestMessage', 'RawResponseMessage',
            'HttpProcessingError', 'BadHttpMessage',
            'HttpBadRequest', 'BadStatusLine', 'LineTooLong', 'InvalidHeader',
            'ClientDisconnectedError', 'ClientTimeoutError',
            'FingerprintMismatch', 'HttpProxyError', 'ProxyConnectionError',
           ))
