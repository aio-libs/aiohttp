import re

from aiohttp.web_exceptions import HTTPMovedPermanently
from aiohttp.web_urldispatcher import SystemRoute


__all__ = (
    'middleware',
    'normalize_path_middleware',
)


async def _check_request_resolves(request, path):
    alt_request = request.clone(rel_url=path)

    match_info = await request.app.router.resolve(alt_request)
    alt_request._match_info = match_info

    if not isinstance(match_info.route, SystemRoute):
        return True, alt_request

    return False, request


def middleware(f):
    f.__middleware_version__ = 1
    return f


def normalize_path_middleware(
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

    If append_slash is True append slash when needed. If a resource is
    defined with trailing slash and the request comes without it, it will
    append it automatically.

    If merge_slashes is True, merge multiple consecutive slashes in the
    path into one.
    """

    @middleware
    async def impl(request, handler):
        if isinstance(request.match_info.route, SystemRoute):
            paths_to_check = []
            if '?' in request.raw_path:
                path, query = request.raw_path.split('?', 1)
                query = '?' + query
            else:
                query = ''
                path = request.raw_path

            if merge_slashes:
                paths_to_check.append(re.sub('//+', '/', path))
            if append_slash and not request.path.endswith('/'):
                paths_to_check.append(path + '/')
            if merge_slashes and append_slash:
                paths_to_check.append(
                    re.sub('//+', '/', path + '/'))

            for path in paths_to_check:
                resolves, request = await _check_request_resolves(
                    request, path)
                if resolves:
                    raise redirect_class(request.path + query)

        return await handler(request)

    return impl


def _fix_request_current_app(app):

    @middleware
    async def impl(request, handler):
        with request.match_info.set_current_app(app):
            return await handler(request)
    return impl
