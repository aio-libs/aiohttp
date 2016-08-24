import asyncio

# from aiohttp.web_exceptions import HTTPMovedPermanently, HTTPNotFound
from aiohttp.web_urldispatcher import SystemRoute
from aiohttp.protocol import RawRequestMessage


@asyncio.coroutine
def normalize_path_middleware(app, handler):
    """
    Middleware that normalizes the path of a request. By normalizing it means:

        - Add a trailing slash to the path.
        - Double slashes are replaced by one.
    """

    @asyncio.coroutine
    def middleware(request):

        router = request.app.router
        match_info = yield from router.resolve(request)
        if not isinstance(match_info.route, SystemRoute):
            resp = yield from handler(request)

        elif not request.path.endswith('/'):
            message = RawRequestMessage(
                request.method, request.path + '/', request.version,
                request.headers, request.raw_headers,
                request.keep_alive, None)
            request = request.copy(message=message)
            match_info = yield from router.resolve(request)
            resp = yield from match_info.handler(request)

        else:
            resp = yield from handler(request)

        return resp

    return middleware
