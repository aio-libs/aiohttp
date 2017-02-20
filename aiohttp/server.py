"""simple HTTP server."""

import asyncio
import asyncio.streams
import http.server
import socket
import traceback
import warnings
from collections import deque
from contextlib import suppress
from html import escape as html_escape

from . import hdrs, helpers
from .helpers import TimeService, create_future, ensure_future
from .http import HttpProcessingError, HttpRequestParser, Response
from .log import access_logger, server_logger
from .streams import StreamWriter

__all__ = ('ServerHttpProtocol',)


RESPONSES = http.server.BaseHTTPRequestHandler.responses
DEFAULT_ERROR_MESSAGE = """
<html>
  <head>
    <title>{status} {reason}</title>
  </head>
  <body>
    <h1>{status} {reason}</h1>
    {message}
  </body>
</html>"""


if hasattr(socket, 'SO_KEEPALIVE'):
    def tcp_keepalive(server, transport):
        sock = transport.get_extra_info('socket')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
else:
    def tcp_keepalive(server, transport):  # pragma: no cover
        pass


class ServerHttpProtocol(asyncio.streams.FlowControlMixin, asyncio.Protocol):
    """Simple HTTP protocol implementation.

    ServerHttpProtocol handles incoming HTTP request. It reads request line,
    request headers and request payload and calls handle_request() method.
    By default it always returns with 404 response.

    ServerHttpProtocol handles errors in incoming request, like bad
    status line, bad headers or incomplete payload. If any error occurs,
    connection gets closed.

    :param time_service: Low resolution time service

    :param keepalive_timeout: number of seconds before closing
                              keep-alive connection
    :type keepalive_timeout: int or None

    :param bool tcp_keepalive: TCP keep-alive is on, default is on

    :param bool debug: enable debug mode

    :param logger: custom logger object
    :type logger: aiohttp.log.server_logger

    :param access_log: custom logging object
    :type access_log: aiohttp.log.server_logger

    :param str access_log_format: access log format string

    :param loop: Optional event loop

    :param int max_line_size: Optional maximum header line size

    :param int max_field_size: Optional maximum header field size

    :param int max_headers: Optional maximum header size

    """
    _request_count = 0
    _reading_request = False
    _keepalive = False  # keep transport open

    def __init__(self, *, loop=None,
                 time_service=None,
                 keepalive_timeout=75,  # NGINX default value is 75 secs
                 tcp_keepalive=True,
                 slow_request_timeout=None,
                 logger=server_logger,
                 access_log=access_logger,
                 access_log_format=helpers.AccessLogger.LOG_FORMAT,
                 debug=False,
                 max_line_size=8190,
                 max_headers=32768,
                 max_field_size=8190,
                 lingering_time=30.0,
                 lingering_timeout=5.0,
                 max_concurrent_handlers=2,
                 **kwargs):

        # process deprecated params
        logger = kwargs.get('logger', logger)

        if slow_request_timeout is not None:
            warnings.warn(
                'slow_request_timeout is deprecated', DeprecationWarning)

        super().__init__(loop=loop)

        self._loop = loop if loop is not None else asyncio.get_event_loop()
        if time_service is not None:
            self._time_service_owner = False
            self._time_service = time_service
        else:
            self._time_service_owner = True
            self._time_service = TimeService(self._loop)

        self._tcp_keepalive = tcp_keepalive
        self._keepalive_handle = None
        self._keepalive_timeout = keepalive_timeout
        self._lingering_time = float(lingering_time)
        self._lingering_timeout = float(lingering_timeout)

        self._messages = deque()
        self._message_tail = b''

        self._waiters = deque()
        self._reading_request = False
        self._request_handlers = []
        self._max_concurrent_handlers = max_concurrent_handlers

        self._upgrade = False
        self._payload_parser = None
        self._request_parser = HttpRequestParser(
            self, loop,
            max_line_size=max_line_size,
            max_field_size=max_field_size,
            max_headers=max_headers)

        self.transport = None
        self._reading_paused = False

        self.logger = logger
        self.debug = debug
        self.access_log = access_log
        if access_log:
            self.access_logger = helpers.AccessLogger(
                access_log, access_log_format)
        else:
            self.access_logger = None
        self._closing = False

    @property
    def time_service(self):
        return self._time_service

    @property
    def keepalive_timeout(self):
        return self._keepalive_timeout

    @asyncio.coroutine
    def shutdown(self, timeout=15.0):
        """Worker process is about to exit, we need cleanup everything and
        stop accepting requests. It is especially important for keep-alive
        connections."""
        if not self._request_handlers:
            if self.transport is not None:
                self.transport.close()
                self.transport = None
            return

        closing, self._closing = self._closing, True

        if self._keepalive_handle is not None:
            self._keepalive_handle.cancel()

        if self._request_count and timeout and not closing:
            with suppress(asyncio.CancelledError):
                with self.time_service.timeout(timeout):
                    while self._request_handlers:
                        h = None
                        for handler in self._request_handlers:
                            if not handler.done():
                                h = handler
                                break
                        if h:
                            yield from h
                        else:
                            break

        # force-close idle keep-alive connections
        for handler in self._request_handlers:
            if not handler.done():
                handler.cancel()

        if self.transport is not None:
            self.transport.close()
            self.transport = None

        self._request_handlers.clear()

    def connection_made(self, transport):
        super().connection_made(transport)

        self.transport = transport
        self.writer = StreamWriter(self, transport, self._loop)

        if self._tcp_keepalive:
            tcp_keepalive(self, transport)

        self.writer.set_tcp_nodelay(True)

    def connection_lost(self, exc):
        super().connection_lost(exc)

        self._closing = True
        self._request_parser = None
        self.transport = self.writer = None

        if self._payload_parser is not None:
            self._payload_parser.feed_eof()
            self._payload_parser = None

        if self._keepalive_handle is not None:
            self._keepalive_handle.cancel()

        for handler in self._request_handlers:
            if not handler.done():
                handler.cancel()

        self._request_handlers = ()

        if self._time_service_owner:
            self._time_service.close()

    def set_parser(self, parser):
        assert self._payload_parser is None

        self._payload_parser = parser

        if self._message_tail:
            self._payload_parser.feed_data(self._message_tail)
            self._message_tail = b''

    def eof_received(self):
        pass

    def data_received(self, data):
        if self._closing:
            return

        while self._messages:
            if self._waiters:
                waiter = self._waiters.popleft()
                message = self._messages.popleft()
                waiter.set_result(message)
            else:
                break

        # parse http messages
        if self._payload_parser is None and not self._upgrade:
            try:
                messages, upgraded, tail = self._request_parser.feed_data(data)
            except HttpProcessingError as exc:
                # something happened during parsing
                self._closing = True
                self._request_handlers.append(
                    ensure_future(
                        self.handle_error(
                            400, None,
                            None, exc, exc.headers, exc.message),
                        loop=self._loop))
                return
            except Exception as exc:
                self._closing = True
                self._request_handlers.append(
                    ensure_future(
                        self.handle_error(500, None, None, exc),
                        loop=self._loop))
                return

            for (msg, payload) in messages:
                self._request_count += 1
                self._reading_request = True

                if self._waiters:
                    waiter = self._waiters.popleft()
                    waiter.set_result((msg, payload))
                elif self._max_concurrent_handlers:
                    self._max_concurrent_handlers -= 1
                    handler = ensure_future(
                        self.start(msg, payload), loop=self._loop)
                    self._request_handlers.append(handler)
                else:
                    self._messages.append((msg, payload))

            self._upgraded = upgraded
            if upgraded:
                self._message_tail = tail

        # no parser, just store
        elif self._payload_parser is None and self._upgrade and data:
            self._message_tail += data

        # feed payload
        elif data:
            eof, tail = self._payload_parser.feed_data(data)
            if eof:
                self._closing = True

    def keep_alive(self, val):
        """Set keep-alive connection mode.

        :param bool val: new state.
        """
        self._keepalive = val

    def log_access(self, message, environ, response, time):
        if self.access_logger:
            self.access_logger.log(message, environ, response,
                                   self.transport, time)

    def log_debug(self, *args, **kw):
        if self.debug:
            self.logger.debug(*args, **kw)

    def log_exception(self, *args, **kw):
        self.logger.exception(*args, **kw)

    def _process_keepalive(self):
        if self._closing:
            return

        if self._request_handlers:
            self._keepalive_handle = self._time_service.call_later(
                self._keepalive_timeout, self._process_keepalive)

        elif self.transport is not None:
            self.transport.close()

    @property
    def _request_handler(self):
        return self._request_handlers[-1]

    def pause_reading(self):
        if not self._reading_paused:
            try:
                self.transport.pause_reading()
            except (AttributeError, NotImplementedError, RuntimeError):
                pass
            self._reading_paused = True

    def resume_reading(self):
        if self._reading_paused:
            try:
                self.transport.resume_reading()
            except (AttributeError, NotImplementedError, RuntimeError):
                pass
            self._reading_paused = False

    @asyncio.coroutine
    def start(self, message, payload):
        """Start processing of incoming requests.

        It reads request line, request headers and request payload, then
        calls handle_request() method. Subclass has to override
        handle_request(). start() handles various exceptions in request
        or response handling. Connection is being closed always unless
        keep_alive(True) specified.
        """
        loop = self._loop
        handler = self._request_handlers[-1]
        time_service = self.time_service

        while not self._closing:
            try:
                yield from self.handle_request(message, payload)

                if not payload.is_eof() and not self._closing:
                    self.log_debug('Uncompleted request.')
                    self._closing = True

                    if self._lingering_time:
                        self.transport.write_eof()
                        self.log_debug(
                            'Start lingering close timer for %s sec.',
                            self._lingering_time)

                        now = time_service.time()
                        end_time = now + self._lingering_time

                        with suppress(asyncio.TimeoutError):
                            while (not payload.is_eof() and
                                   now < end_time):
                                timeout = min(
                                    end_time - now, self._lingering_timeout)
                                with time_service.timeout(timeout):
                                    # read and ignore
                                    yield from payload.readany()
                                now = time_service.time()
            except asyncio.CancelledError:
                self._closing = True
                self.log_debug('Ignored premature client disconnection')
            except asyncio.TimeoutError:
                self._closing = True
                self.log_debug('Request handler timed out.')
                yield from self.handle_error(504, message)
            except Exception as exc:
                self._closing = True
                yield from self.handle_error(500, message, None, exc)
            finally:
                if self.transport is None:
                    self.log_debug(
                        'Ignored premature client disconnection #2.')
                    return
                elif not self._closing:
                    if self._messages:
                        message, payload = self._messages.popleft()
                    else:
                        if not self._keepalive:
                            self._closing = True
                            self.transport.close()
                        else:
                            waiter = create_future(loop)
                            self._waiters.append(waiter)
                            message, payload = yield from waiter
                else:
                    self._request_handlers.remove(handler)

                    if (not self._request_handlers and
                            self.transport is not None):
                        self.transport.close()

    @asyncio.coroutine
    def handle_error(self, status=500, message=None,
                     payload=None, exc=None, headers=None, reason=None):
        """Handle errors.

        Returns HTTP response with specific status code. Logs additional
        information. It always closes current connection."""
        if self.access_log:
            now = self._loop.time()
        try:
            if self.transport is None:
                # client has been disconnected during writing.
                return

            if status == 500:
                self.log_exception("Error handling request")

            try:
                if reason is None or reason == '':
                    reason, msg = RESPONSES[status]
                else:
                    msg = reason
            except KeyError:
                status = 500
                reason, msg = '???', ''

            if self.debug and exc is not None:
                try:
                    tb = traceback.format_exc()
                    tb = html_escape(tb)
                    msg += '<br><h2>Traceback:</h2>\n<pre>{}</pre>'.format(tb)
                except:
                    pass

            html = DEFAULT_ERROR_MESSAGE.format(
                status=status, reason=reason, message=msg).encode('utf-8')

            response = Response(
                self.writer, status, close=True, loop=self._loop)
            response.add_header(hdrs.CONTENT_TYPE, 'text/html; charset=utf-8')
            response.add_header(hdrs.CONTENT_LENGTH, str(len(html)))
            response.add_header(hdrs.DATE, self._time_service.strtime())
            if headers is not None:
                for name, value in headers:
                    response.add_header(name, value)
            response.send_headers()

            response.write(html)
            # disable CORK, enable NODELAY if needed
            self.writer.set_tcp_nodelay(True)
            yield from response.write_eof()

            if self.access_log:
                self.log_access(
                    message, None, response, self._loop.time() - now)
        finally:
            self.keep_alive(False)

    @asyncio.coroutine
    def handle_request(self, message, payload):
        """Handle a single HTTP request.

        Subclass should override this method. By default it always
        returns 404 response.

        :param message: Request headers
        :type message: aiohttp.protocol.HttpRequestParser
        :param payload: Request payload
        :type payload: aiohttp.streams.FlowControlStreamReader
        """
        if self.access_log:
            now = self._loop.time()
        response = Response(
            self.writer, 404,
            http_version=message.version, close=True, loop=self._loop)

        body = b'Page Not Found!'

        response.add_header(hdrs.CONTENT_TYPE, 'text/plain')
        response.add_header(hdrs.CONTENT_LENGTH, str(len(body)))
        response.add_header(hdrs.DATE, self._time_service.strtime())
        response.send_headers()
        response.write(body)
        yield from response.write_eof()

        self.keep_alive(False)
        if self.access_log:
            self.log_access(message, None, response, self._loop.time() - now)
