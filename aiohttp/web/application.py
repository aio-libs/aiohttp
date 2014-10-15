import asyncio

from ..errors import HttpErrorException
from ..server import ServerHttpProtocol

from .request import ServerRequest, ServerResponse
from .urldispatch import UrlDispatch


__all__ = ['Application']


class RequestHandler(ServerHttpProtocol):

    def __init__(self, application, **kwargs):
        super().__init__(**kwargs)
        self._application = application

    @asyncio.coroutine
    def handle_request(self, message, payload):
        request = ServerRequest(self._application, message, payload,
                                self, loop=self._loop)
        match_info = yield from self._application.router.resolve(request)
        if match_info is not None:
            request._match_info = match_info
            handler = match_info.handler

            if asyncio.iscoroutinefunction(handler):
                resp = yield from handler(request)
            else:
                resp = handler(request)
            yield from request.release()

            if resp is not None:
                if not isinstance(resp, ServerResponse):
                    raise RuntimeError(("Handler should return ServerResponse "
                                       "instance, got {!r}")
                                       .format(type(resp)))
                yield from resp.render()
            else:
                resp = request._response
            yield from resp.write_eof()
        else:
            raise HttpErrorException(404, "Not Found")


class Application(dict, asyncio.AbstractServer):

    def __init__(self, host, *, loop=None, router=None, **kwargs):
        self._host = host
        self._kwargs = kwargs
        if loop is None:
            loop = asyncio.get_event_loop()
        if router is None:
            router = UrlDispatch(loop=loop)
        self._router = router

    @property
    def host(self):
        return self._host

    @property
    def router(self):
        return self._router

    def make_handler(self):
        return RequestHandler(self, **self._kwargs)

    def close(self):
        pass

    def register_on_close(self, cb):
        pass

    @asyncio.coroutine
    def wait_closed(self):
        pass
