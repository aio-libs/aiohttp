__version__ = '3.1.1'

# This relies on each of the submodules having an __all__ variable.

from . import hdrs  # noqa
from .client import *  # noqa
from .cookiejar import *  # noqa
from .formdata import *  # noqa
from .helpers import *  # noqa
from .http import (HttpVersion, HttpVersion10, HttpVersion11,  # noqa
                   WSMsgType, WSCloseCode, WSMessage, WebSocketError)  # noqa
from .multipart import *  # noqa
from .payload import *  # noqa
from .payload_streamer import *  # noqa
from .resolver import *  # noqa
from .signals import *  # noqa
from .streams import *  # noqa
from .tracing import *  # noqa

try:
    from .worker import GunicornWebWorker, GunicornUVLoopWebWorker  # noqa
    workers = ('GunicornWebWorker', 'GunicornUVLoopWebWorker')
except ImportError:  # pragma: no cover
    workers = ()


__all__ = (client.__all__ +  # noqa
           cookiejar.__all__ +  # noqa
           formdata.__all__ +  # noqa
           helpers.__all__ +  # noqa
           multipart.__all__ +  # noqa
           payload.__all__ +  # noqa
           payload_streamer.__all__ +  # noqa
           streams.__all__ +  # noqa
           signals.__all__ +  # noqa
           tracing.__all__ + # noqa
           ('hdrs', 'HttpVersion', 'HttpVersion10', 'HttpVersion11',
            'WSMsgType', 'WSCloseCode',
            'WebSocketError', 'WSMessage',
           ) + workers)
