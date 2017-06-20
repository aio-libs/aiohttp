__version__ = '2.2.0'

# This relies on each of the submodules having an __all__ variable.

from . import hdrs  # noqa
from .client import *  # noqa
from .formdata import *  # noqa
from .helpers import *  # noqa
from .http import (HttpVersion, HttpVersion10, HttpVersion11,  # noqa
                   WSMsgType, WSCloseCode, WSMessage, WebSocketError)  # noqa
from .streams import *  # noqa
from .multipart import *  # noqa
from .cookiejar import CookieJar  # noqa
from .payload import *  # noqa
from .payload_streamer import *  # noqa
from .resolver import *  # noqa

try:
    from .worker import GunicornWebWorker, GunicornUVLoopWebWorker  # noqa
    workers = ('GunicornWebWorker', 'GunicornUVLoopWebWorker')
except ImportError:
    workers = ()


__all__ = (client.__all__ +  # noqa
           formdata.__all__ +  # noqa
           helpers.__all__ +  # noqa
           multipart.__all__ +  # noqa
           payload.__all__ +  # noqa
           payload_streamer.__all__ +  # noqa
           streams.__all__ +  # noqa
           ('hdrs', 'HttpVersion', 'HttpVersion10', 'HttpVersion11',
            'WSMsgType', 'WSCloseCode',
            'WebSocketError', 'WSMessage', 'CookieJar',
           ) + workers)
