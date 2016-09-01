import asyncio
import re

from aiohttp.web_urldispatcher import SystemRoute


@asyncio.coroutine
def _check_request_resolves(request, path):
    alt_request = request.clone(path=path)

    match_info = yield from request.app.router.resolve(alt_request)
    alt_request._match_info = match_info

    if not isinstance(match_info.route, SystemRoute):
        return True, alt_request

    return False, request


def normalize_path(*, append_slash=True, merge_slashes=True):
    """
    Middleware that normalizes the path of a request. By normalizing
    it means:

        - Add a trailing slash to the path.
        - Double slashes are replaced by one.

    The middleware returns as soon as it finds a path that resolves
    correctly. The order if all enable is 1) merge_slashes, 2) append_slash
    and 3) both merge_slashes and append_slash.

    :param append_slash: If True append slash when needed. If a resource is
    defined with trailing slash and the request comes without it, it will
    append it automatically.
    :param merge_slashes: If True, merge multiple consecutive slashes in the
    path into one.
    """

    @asyncio.coroutine
    def normalize_path_factory(app, handler):

        @asyncio.coroutine
        def middleware(request):

            if not isinstance(request.match_info.route, SystemRoute):
                return (yield from handler(request))

            else:
                if merge_slashes:
                    resolves, request = yield from _check_request_resolves(
                        request, re.sub('//+', '/', request.path))
                    if resolves:
                        return (yield from request.match_info.handler(request))

                if append_slash:
                    resolves, request = yield from _check_request_resolves(
                        request, request.path + '/')
                    if resolves:
                        return (yield from request.match_info.handler(request))

                if merge_slashes and append_slash:
                    resolves, request = yield from _check_request_resolves(
                        request, re.sub('//+', '/', request.path + '/'))
                    if resolves:
                        return (yield from request.match_info.handler(request))

            return (yield from handler(request))

        return middleware

    return normalize_path_factory
