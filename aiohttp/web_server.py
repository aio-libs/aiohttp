"""Low level HTTP server."""

import asyncio
import traceback
from html import escape as html_escape

from . import errors
from .helpers import TimeService
from .server import ServerHttpProtocol
from .web_exceptions import HTTPException, HTTPInternalServerError
from .web_reqrep import BaseRequest

__all__ = ('RequestHandler', 'Server')


class RequestHandler(ServerHttpProtocol):
    _request = None

    def __init__(self, manager, **kwargs):
        kwargs['time_service'] = manager.time_service

        super().__init__(**kwargs)

        self._manager = manager
        self._request_factory = manager.request_factory
        self._handler = manager.handler

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
        self._request_factory = None
        self._manager = None
        self._handler = None

    @asyncio.coroutine
    def handle_request(self, message, payload):
        self._manager._requests_count += 1
        if self.access_log:
            now = self._loop.time()

        request = self._request_factory(message, payload, self)
        self._request = request

        try:
            resp = yield from self._handler(request)
        except (asyncio.CancelledError,
                asyncio.TimeoutError,
                errors.ClientDisconnectedError) as exc:
            raise
        except HTTPException as exc:
            resp = exc
        except Exception as exc:
            msg = "<h1>500 Internal Server Error</h1>"
            if self.debug:
                try:
                    tb = traceback.format_exc()
                    tb = html_escape(tb)
                    msg += '<br><h2>Traceback:</h2>\n<pre>'
                    msg += tb
                    msg += '</pre>'
                except:  # pragma: no cover
                    pass
            else:
                msg += "Server got itself in trouble"
            msg = ("<html><head><title>500 Internal Server Error</title>"
                   "</head><body>" + msg + "</body></html>")
            resp = HTTPInternalServerError(
                text=msg, content_type='text/html')
            self.logger.exception(
                "Error handling request",
                exc_info=exc)

        if not resp.prepared:
            yield from resp.prepare(request)
        yield from resp.write_eof()

        # notify server about keep-alive
        # assign to parent class attr
        self._keepalive = resp.keep_alive

        # Restore default state.
        # Should be no-op if server code didn't touch these attributes.
        self.writer.set_tcp_cork(False)
        self.writer.set_tcp_nodelay(True)

        # log access
        if self.access_log:
            self.log_access(message, None, resp, self._loop.time() - now)

        # for repr
        self._request = None


class Server:

    def __init__(self, handler, *, request_factory=None, loop=None, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._handler = handler
        self._request_factory = request_factory or self._make_request
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
    def handler(self):
        return self._handler

    @property
    def request_factory(self):
        return self._request_factory

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

    def _make_request(self, message, payload, protocol):
        return BaseRequest(
            message, payload,
            protocol.transport, protocol.reader, protocol.writer,
            protocol.time_service, protocol._request_handler)

    @asyncio.coroutine
    def shutdown(self, timeout=None):
        coros = [conn.shutdown(timeout) for conn in self._connections]
        yield from asyncio.gather(*coros, loop=self._loop)
        self._connections.clear()
        self._time_service.close()

    finish_connections = shutdown

    def __call__(self):
        return RequestHandler(
            self, loop=self._loop,
            **self._kwargs)
