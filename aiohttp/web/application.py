import asyncio

from ..errors import HttpErrorException
from ..server import ServerHttpProtocol

from .request import Request, Response
from .urldispatch import UrlDispatch


__all__ = ['Application']


class RequestHandler(ServerHttpProtocol):

    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self._app = app

    @asyncio.coroutine
    def handle_request(self, message, payload):
        request = Request(self._app, message, payload,
                          self, loop=self._loop)
        match_info = yield from self._app.router.resolve(request)
        if match_info is not None:
            request._match_info = match_info
            handler = match_info.handler

            if asyncio.iscoroutinefunction(handler):
                resp = yield from handler(request)
            else:
                resp = handler(request)
            yield from request.release()

            if resp is not None:
                if isinstance(resp, Response):
                    yield from resp.render()
                else:
                    raise RuntimeError(("Handler should return Response "
                                       "instance, got {!r}")
                                       .format(type(resp)))
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
        self._loop = loop

    @property
    def host(self):
        return self._host

    @property
    def router(self):
        return self._router

    def make_handler(self):
        return RequestHandler(self, lop=self._loop, **self._kwargs)

    def close(self):
        pass

    def register_on_close(self, cb):
        pass

    @asyncio.coroutine
    def wait_closed(self):
        pass
