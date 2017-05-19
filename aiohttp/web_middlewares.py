import asyncio
import re
import logging

from aiohttp.web_exceptions import HTTPException, HTTPInternalServerError, HTTPMovedPermanently
from aiohttp.web_urldispatcher import SystemRoute

__all__ = (
    'normalize_path_middleware',
)


@asyncio.coroutine
def _check_request_resolves(request, path):
    alt_request = request.clone(rel_url=path)

    match_info = yield from request.app.router.resolve(alt_request)
    alt_request._match_info = match_info

    if not isinstance(match_info.route, SystemRoute):
        return True, alt_request

    return False, request


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

    @asyncio.coroutine
    def normalize_path_factory(app, handler):

        @asyncio.coroutine
        def middleware(request):

            if isinstance(request.match_info.route, SystemRoute):
                paths_to_check = []
                path = request.raw_path
                if merge_slashes:
                    paths_to_check.append(re.sub('//+', '/', path))
                if append_slash and not request.path.endswith('/'):
                    paths_to_check.append(path + '/')
                if merge_slashes and append_slash:
                    paths_to_check.append(
                        re.sub('//+', '/', path + '/'))

                for path in paths_to_check:
                    resolves, request = yield from _check_request_resolves(
                        request, path)
                    if resolves:
                        return redirect_class(request.path)

            return (yield from handler(request))

        return middleware

    return normalize_path_factory


class ErrorLoggingMiddleware:
    """
    Middleware for logging exceptions occurring while processing requests,
    also capable of logging warnings - eg. for responses with status >= 400.
    
    This is setup to play nicely with sentry (https://sentry.io) but just uses
    vanilla python logging so could be used to report exceptions and warnings
    with any logging setup you like.
    """
    def __init__(self, log_name='aiohttp.server', log_warnings=True):
        self.logger = logging.getLogger(log_name)
        self.should_log_warnings = log_warnings

    async def log_extra_data(self, request, response=None):
        return dict(
            request_url=str(request.rel_url),
            request_method=request.method,
            request_host=request.host,
            request_headers=dict(request.headers),
            request_text=response and await request.text(),
            response_status=response and response.status,
            response_headers=response and dict(response.headers),
            response_text=response and response.text,
        )

    async def log_warning(self, request, response):
        self.logger.warning('%s %d', request.rel_url, response.status, extra={
            'fingerprint': [request.rel_url, str(response.status)],
            'data': await self.log_extra_data(request, response)
        })

    async def log_exception(self, exc, request):
        self.logger.exception('%s: %s', exc.__class__.__name__, exc, extra={
            'data': await self.log_extra_data(request)
        })

    async def __call__(self, app, handler):
        async def _handler(request):
            try:
                http_exception = getattr(
                    request.match_info, 'http_exception', None
                )
                if http_exception:
                    raise http_exception
                else:
                    r = await handler(request)
            except HTTPException as e:
                if self.should_log_warnings and e.status >= 400:
                    await self.log_warning(request, e)
                raise
            except BaseException as e:
                await self.log_exception(e, request)
                raise HTTPInternalServerError()
            else:
                if self.should_log_warnings and r.status >= 400:
                    await self.log_warning(request, r)
                return r
        return _handler
