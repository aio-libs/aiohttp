from asyncio import AbstractEventLoop
from .helpers import NO_EXTENSIONS


if NO_EXTENSIONS:
    HAS_AIOFASTNET = False
else:
    try:
        import aiofastnet
        HAS_AIOFASTNET = True

        create_connection = aiofastnet.create_connection
        start_tls = aiofastnet.start_tls
        create_server = aiofastnet.create_server
        sendfile = aiofastnet.sendfile
    except ImportError:
        HAS_AIOFASTNET = False


if not HAS_AIOFASTNET:
    async def create_connection(loop: AbstractEventLoop, *args, **kwargs): # type: ignore[no-untyped-def]
        return await loop.create_connection(*args, **kwargs)

    async def start_tls(loop: AbstractEventLoop, *args, **kwargs): # type: ignore[no-untyped-def]
        return await loop.start_tls(*args, **kwargs)

    async def create_server(loop: AbstractEventLoop, *args, **kwargs): # type: ignore[no-untyped-def]
        return await loop.create_server(*args, **kwargs)

    async def sendfile(loop: AbstractEventLoop, *args, **kwargs): # type: ignore[no-untyped-def]
        return await loop.sendfile(*args, **kwargs)

