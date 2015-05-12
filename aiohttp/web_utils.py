import asyncio

from aiohttp.web_exceptions import HTTPMovedPermanently, HTTPNotFound
from aiohttp.web_urldispatcher import SystemRoute

__all__ = ('normalize_path_middleware',)


def normalize_path_middleware(*, merge_slashes=True, append_slash=True,
                              redirect_class=HTTPMovedPermanently):

    @asyncio.coroutine
    def factory(app, handler):

        @asyncio.coroutine
        def middleware(request):
            try:
                return (yield from handler(request))
            except HTTPNotFound as exc:
                router = request.app.router
                if merge_slashes:
                    if '//' in request.path:
                        path = request.path
                        while True:
                            path = path.replace('//', '/')
                            if '//' not in path:
                                break

                        match_info = yield from router.resolve2(request.method,
                                                                path)
                        if not isinstance(match_info.route, SystemRoute):
                            url = path
                            if request.query_string:
                                url += '?' + request.query_string
                            return redirect_class(url)
                if append_slash:
                    if not request.path.endswith('/'):
                        path = request.path + '/'
                        match_info = yield from router.resolve2(request.method,
                                                                path)
                        if not isinstance(match_info.route, SystemRoute):
                            url = path
                            if request.query_string:
                                url += '?' + request.query_string
                            return redirect_class(url)
                raise exc

        return middleware

    return factory
