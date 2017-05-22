"""Low level HTTP server."""
import asyncio

from .helpers import TimeService
from .web_protocol import RequestHandler
from .web_request import BaseRequest


__all__ = ('Server',)


class Server:

    def __init__(self, handler, *, request_factory=None, loop=None, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._connections = {}
        self._kwargs = kwargs
        self.time_service = TimeService(self._loop)
        self.requests_count = 0
        self.request_handler = handler
        self.request_factory = request_factory or self._make_request

    @property
    def connections(self):
        return list(self._connections.keys())

    def connection_made(self, handler, transport):
        self._connections[handler] = transport

    def connection_lost(self, handler, exc=None):
        if handler in self._connections:
            del self._connections[handler]

    def _make_request(self, message, payload, protocol, writer, task):
        return BaseRequest(
            message, payload, protocol, writer,
            protocol.time_service, task)

    @asyncio.coroutine
    def shutdown(self, timeout=None):
        coros = [conn.shutdown(timeout) for conn in self._connections]
        yield from asyncio.gather(*coros, loop=self._loop)
        self._connections.clear()
        self.time_service.close()

    finish_connections = shutdown

    def __call__(self):
        return RequestHandler(self, loop=self._loop, **self._kwargs)
