import asyncio
import re

from aiohttp.web_exceptions import HTTPMovedPermanently
from aiohttp.web_urldispatcher import SystemRoute


@asyncio.coroutine
def _check_request_resolves(request, path):
    alt_request = request.clone(path=path)

    match_info = yield from request.app.router.resolve(alt_request)
    alt_request._match_info = match_info

    if not isinstance(match_info.route, SystemRoute):
        return True, alt_request

    return False, request


def normalize_path(
        *, append_slash=True, merge_slashes=True,
        redirect_class=HTTPMovedPermanently):
    """
    Middleware that normalizes the path of a request. By normalizing
    it means:

        - Add a trailing slash to the path.
        - Double slashes are replaced by one.

    The middleware returns as soon as it finds a path that resolves
    correctly. The order if all enable is 1) merge_slashes, 2) append_slash
    and 3) both merge_slashes and append_slash. If the path resolves with
    at least one of those conditions, it will redirect to the new path.

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

            if isinstance(request.match_info.route, SystemRoute):
                paths_to_check = []
                if merge_slashes:
                    paths_to_check.append(re.sub('//+', '/', request.path))
                if append_slash:
                    paths_to_check.append(request.path + '/')
                if merge_slashes and append_slash:
                    paths_to_check.append(
                        re.sub('//+', '/', request.path + '/'))

                for path in paths_to_check:
                    resolves, request = yield from _check_request_resolves(
                        request, path)
                    if resolves:
                        return redirect_class(request.path)

            return (yield from handler(request))

        return middleware

    return normalize_path_factory
