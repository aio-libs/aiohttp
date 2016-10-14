__version__ = '1.0.5'

# Deprecated, keep it here for a while for backward compatibility.
import multidict  # noqa

# This relies on each of the submodules having an __all__ variable.

from multidict import *  # noqa
from . import hdrs  # noqa
from .protocol import *  # noqa
from .connector import *  # noqa
from .client import *  # noqa
from .client_reqrep import *  # noqa
from .errors import *  # noqa
from .helpers import *  # noqa
from .parsers import *  # noqa
from .streams import *  # noqa
from .multipart import *  # noqa
from .client_ws import ClientWebSocketResponse  # noqa
from ._ws_impl import WSMsgType, WSCloseCode, WSMessage, WebSocketError  # noqa
from .file_sender import FileSender  # noqa
from .cookiejar import CookieJar  # noqa
from .resolver import *  # noqa


MsgType = WSMsgType  # backward compatibility


__all__ = (client.__all__ +  # noqa
           client_reqrep.__all__ +  # noqa
           errors.__all__ +  # noqa
           helpers.__all__ +  # noqa
           parsers.__all__ +  # noqa
           protocol.__all__ +  # noqa
           connector.__all__ +  # noqa
           streams.__all__ +  # noqa
           multidict.__all__ +  # noqa
           multipart.__all__ +  # noqa
           ('hdrs', 'FileSender', 'WSMsgType', 'MsgType', 'WSCloseCode',
            'WebSocketError', 'WSMessage',
            'ClientWebSocketResponse', 'CookieJar'))
