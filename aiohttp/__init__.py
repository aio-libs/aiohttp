__version__ = '2.0.0a0'

# This relies on each of the submodules having an __all__ variable.

from . import hdrs  # noqa
from .connector import *  # noqa
from .client import *  # noqa
from .client_reqrep import *  # noqa
from .errors import *  # noqa
from .helpers import *  # noqa
from .http_message import HttpVersion, HttpVersion10, HttpVersion11  # noqa
from .streams import *  # noqa
from .multipart import *  # noqa
from .client_ws import ClientWebSocketResponse  # noqa
from ._ws_impl import WSMsgType, WSCloseCode, WSMessage, WebSocketError  # noqa
from .file_sender import FileSender  # noqa
from .cookiejar import CookieJar  # noqa
from .resolver import *  # noqa

# deprecated #1657
from .http_message import HttpMessage, Request, Response  # noqa isort:skip
from .http_parser import HttpRequestParser, HttpResponseParser  # noqa isort:skip
from .http_exceptions import HttpProcessingError, BadHttpMessage  # noqa isort:skip
from .http_exceptions import HttpBadRequest, BadStatusLine, LineTooLong, InvalidHeader  # noqa isort:skip


MsgType = WSMsgType  # backward compatibility


__all__ = (client.__all__ +  # noqa
           client_reqrep.__all__ +  # noqa
           errors.__all__ +  # noqa
           helpers.__all__ +  # noqa
           connector.__all__ +  # noqa
           streams.__all__ +  # noqa
           multipart.__all__ +  # noqa
           ('hdrs', 'FileSender',
            'HttpVersion', 'HttpVersion10', 'HttpVersion11',
            'WSMsgType', 'MsgType', 'WSCloseCode',
            'WebSocketError', 'WSMessage',
            'ClientWebSocketResponse', 'CookieJar',

            # deprecated api #1657
            'HttpMessage', 'Request', 'Response',
            'HttpRequestParser', 'HttpResponseParser',
            'RawRequestMessage', 'RawResponseMessage',
            'HttpProcessingError', 'BadHttpMessage',
            'HttpBadRequest', 'BadStatusLine', 'LineTooLong', 'InvalidHeader'
           ))
