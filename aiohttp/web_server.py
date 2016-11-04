"""Low level HTTP server."""

import asyncio
from abc import ABC, abstractmethod

from .helpers import TimeService
from .server import ServerHttpProtocol
from .web_exceptions import HTTPException
from .web_reqrep import BaseRequest


class BaseRequestHandler(ServerHttpProtocol, ABC):
    _request = None

    def __init__(self, manager, **kwargs):
        super().__init__(**kwargs)
        self._manager = manager
        self._time_service = manager.time_service

    def __repr__(self):
        if self._request is None:
            meth = 'none'
            path = 'none'
        else:
            meth = self._request.method
            path = self._request.rel_url.raw_path
        return "<{} {}:{} {}>".format(
            self.__class__.__name__, meth, path,
            'connected' if self.transport is not None else 'disconnected')

    def connection_made(self, transport):
        super().connection_made(transport)

        self._manager.connection_made(self, transport)

    def connection_lost(self, exc):
        self._manager.connection_lost(self, exc)

        super().connection_lost(exc)

    def make_request(self, message, payload):
        return BaseRequest(
            message, payload,
            self.transport, self.reader, self.writer,
            self._time_service)

    @abstractmethod
    @asyncio.coroutine
    def handle(self, request):
        pass

    @asyncio.coroutine
    def handle_request(self, message, payload):
        self._manager._requests_count += 1
        if self.access_log:
            now = self._loop.time()

        request = self.make_request(message, payload)
        self._request = request

        try:
            resp = yield from self.handle(request)
        except HTTPException as exc:
            resp = exc

        resp_msg = yield from resp.prepare(request)
        yield from resp.write_eof()

        # notify server about keep-alive
        self.keep_alive(resp.keep_alive)

        # Restore default state.
        # Should be no-op if server code didn't touch these attributes.
        self.writer.set_tcp_cork(False)
        self.writer.set_tcp_nodelay(True)

        # log access
        if self.access_log:
            self.log_access(message, None, resp_msg, self._loop.time() - now)

        # for repr
        self._request = None


class BaseRequestHandlerFactory:

    def __init__(self, *, handler=BaseRequestHandler, loop=None, **kwargs):
        self._handler = handler
        self._loop = loop
        self._connections = {}
        self._kwargs = kwargs
        self._requests_count = 0
        self._time_service = TimeService(self._loop)

    @property
    def requests_count(self):
        """Number of processed requests."""
        return self._requests_count

    @property
    def time_service(self):
        return self._time_service

    @property
    def connections(self):
        return list(self._connections.keys())

    def connection_made(self, handler, transport):
        self._connections[handler] = transport

    def connection_lost(self, handler, exc=None):
        if handler in self._connections:
            del self._connections[handler]

    @asyncio.coroutine
    def finish_connections(self, timeout=None):
        coros = [conn.shutdown(timeout) for conn in self._connections]
        yield from asyncio.gather(*coros, loop=self._loop)
        self._connections.clear()
        self._time_service.stop()

    def __call__(self):
        return self._handler(
            self, loop=self._loop,
            **self._kwargs)
