# This relies on each of the submodules having an __all__ variable.

__version__ = '0.18.4'


from . import hdrs  # noqa
from .protocol import *  # noqa
from .connector import *  # noqa
from .client import *  # noqa
from .errors import *  # noqa
from .helpers import *  # noqa
from .parsers import *  # noqa
from .streams import *  # noqa
from .multidict import *  # noqa
from .multipart import *  # noqa
from .websocket_client import *  # noqa

# asyncio.async() was renamed to .ensure_future() in 3.4.3/3.5
# because "async" is a keyword in "async def" coroutines
import asyncio
try:
    asyncio.ensure_future
except AttributeError:
    asyncio.ensure_future = getattr(asyncio,'async')
del asyncio

__all__ = (client.__all__ +
           errors.__all__ +
           helpers.__all__ +
           parsers.__all__ +
           protocol.__all__ +
           connector.__all__ +
           streams.__all__ +
           multidict.__all__ +
           multipart.__all__ +
           websocket_client.__all__ +
           ('hdrs', '__version__'))
