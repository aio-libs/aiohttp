import asyncio
import asyncio.streams
import http.server
import traceback
import warnings
from collections import deque
from contextlib import suppress
from html import escape as html_escape

import yarl

from . import helpers, http
from .helpers import CeilTimeout
from .http import HttpProcessingError, HttpRequestParser, StreamWriter
from .log import access_logger, server_logger
from .streams import EMPTY_PAYLOAD
from .tcp_helpers import tcp_cork, tcp_keepalive, tcp_nodelay
from .web_exceptions import HTTPException
from .web_request import BaseRequest
from .web_response import Response


__all__ = ('RequestHandler', 'RequestPayloadError')

ERROR = http.RawRequestMessage(
    'UNKNOWN', '/', http.HttpVersion10, {},
    {}, True, False, False, False, yarl.URL('/'))


class RequestPayloadError(Exception):
    """Payload parsing error."""


class RequestHandler(asyncio.streams.FlowControlMixin, asyncio.Protocol):
    """HTTP protocol implementation.

    RequestHandler handles incoming HTTP request. It reads request line,
    request headers and request payload and calls handle_request() method.
    By default it always returns with 404 response.

    RequestHandler handles errors in incoming request, like bad
    status line, bad headers or incomplete payload. If any error occurs,
    connection gets closed.

    :param keepalive_timeout: number of seconds before closing
                              keep-alive connection
    :type keepalive_timeout: int or None

    :param bool tcp_keepalive: TCP keep-alive is on, default is on

    :param bool debug: enable debug mode

    :param logger: custom logger object
    :type logger: aiohttp.log.server_logger

    :param access_log_class: custom class for access_logger
    :type access_log_class: aiohttp.abc.AbstractAccessLogger

    :param access_log: custom logging object
    :type access_log: aiohttp.log.server_logger

    :param str access_log_format: access log format string

    :param loop: Optional event loop

    :param int max_line_size: Optional maximum header line size

    :param int max_field_size: Optional maximum header field size

    :param int max_headers: Optional maximum header size

    """
    _request_count = 0
    _keepalive = False  # keep transport open
    KEEPALIVE_RESCHEDULE_DELAY = 1

    def __init__(self, manager, *, loop=None,
                 keepalive_timeout=75,  # NGINX default value is 75 secs
                 tcp_keepalive=True,
                 logger=server_logger,
                 access_log_class=helpers.AccessLogger,
                 access_log=access_logger,
                 access_log_format=helpers.AccessLogger.LOG_FORMAT,
                 debug=False,
                 max_line_size=8190,
                 max_headers=32768,
                 max_field_size=8190,
                 lingering_time=10.0):

        super().__init__(loop=loop)

        self._loop = loop if loop is not None else asyncio.get_event_loop()

        self._manager = manager
        self._request_handler = manager.request_handler
        self._request_factory = manager.request_factory

        self._tcp_keepalive = tcp_keepalive
        self._keepalive_time = None
        self._keepalive_handle = None
        self._keepalive_timeout = keepalive_timeout
        self._lingering_time = float(lingering_time)

        self._messages = deque()
        self._message_tail = b''

        self._waiter = None
        self._error_handler = None
        self._task_handler = self._loop.create_task(self.start())

        self._upgrade = False
        self._payload_parser = None
        self._request_parser = HttpRequestParser(
            self, loop,
            max_line_size=max_line_size,
            max_field_size=max_field_size,
            max_headers=max_headers,
            payload_exception=RequestPayloadError)

        self.transport = None
        self._reading_paused = False

        self.logger = logger
        self.debug = debug
        self.access_log = access_log
        if access_log:
            self.access_logger = access_log_class(
                access_log, access_log_format)
        else:
            self.access_logger = None

        self._close = False
        self._force_close = False

    def __repr__(self):
        return "<{} {}>".format(
            self.__class__.__name__,
            'connected' if self.transport is not None else 'disconnected')

    @property
    def keepalive_timeout(self):
        return self._keepalive_timeout

    async def shutdown(self, timeout=15.0):
        """Worker process is about to exit, we need cleanup everything and
        stop accepting requests. It is especially important for keep-alive
        connections."""
        self._force_close = True

        if self._keepalive_handle is not None:
            self._keepalive_handle.cancel()

        if self._waiter:
            self._waiter.cancel()

        # wait for handlers
        with suppress(asyncio.CancelledError, asyncio.TimeoutError):
            with CeilTimeout(timeout, loop=self._loop):
                if self._error_handler and not self._error_handler.done():
                    await self._error_handler

                if self._task_handler and not self._task_handler.done():
                    await self._task_handler

        # force-close non-idle handler
        if self._task_handler:
            self._task_handler.cancel()

        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def connection_made(self, transport):
        super().connection_made(transport)

        self.transport = transport

        if self._tcp_keepalive:
            tcp_keepalive(transport)

        tcp_cork(transport, False)
        tcp_nodelay(transport, True)
        self._manager.connection_made(self, transport)

    def connection_lost(self, exc):
        self._manager.connection_lost(self, exc)

        super().connection_lost(exc)

        self._manager = None
        self._force_close = True
        self._request_factory = None
        self._request_handler = None
        self._request_parser = None
        self.transport = None

        if self._keepalive_handle is not None:
            self._keepalive_handle.cancel()

        if self._task_handler:
            self._task_handler.cancel()

        if self._error_handler is not None:
            self._error_handler.cancel()

        self._task_handler = None

        if self._payload_parser is not None:
            self._payload_parser.feed_eof()
            self._payload_parser = None

    def set_parser(self, parser):
        assert self._payload_parser is None

        self._payload_parser = parser

        if self._message_tail:
            self._payload_parser.feed_data(self._message_tail)
            self._message_tail = b''

    def eof_received(self):
        pass

    def data_received(self, data):
        if self._force_close or self._close:
            return

        # parse http messages
        if self._payload_parser is None and not self._upgrade:
            try:
                messages, upgraded, tail = self._request_parser.feed_data(data)
            except HttpProcessingError as exc:
                # something happened during parsing
                self._error_handler = self._loop.create_task(
                    self.handle_parse_error(
                        StreamWriter(self, self.transport, self._loop),
                        400, exc, exc.message))
                self.close()
            except Exception as exc:
                # 500: internal error
                self._error_handler = self._loop.create_task(
                    self.handle_parse_error(
                        StreamWriter(self, self.transport, self._loop),
                        500, exc))
                self.close()
            else:
                if messages:
                    # sometimes the parser returns no messages
                    for (msg, payload) in messages:
                        self._request_count += 1
                        self._messages.append((msg, payload))

                    waiter = self._waiter
                    if waiter is not None:
                        if not waiter.done():
                            # don't set result twice
                            waiter.set_result(None)

                self._upgrade = upgraded
                if upgraded and tail:
                    self._message_tail = tail

        # no parser, just store
        elif self._payload_parser is None and self._upgrade and data:
            self._message_tail += data

        # feed payload
        elif data:
            eof, tail = self._payload_parser.feed_data(data)
            if eof:
                self.close()

    def keep_alive(self, val):
        """Set keep-alive connection mode.

        :param bool val: new state.
        """
        self._keepalive = val
        if self._keepalive_handle:
            self._keepalive_handle.cancel()
            self._keepalive_handle = None

    def close(self):
        """Stop accepting new pipelinig messages and close
        connection when handlers done processing messages"""
        self._close = True
        if self._waiter:
            self._waiter.cancel()

    def force_close(self, send_last_heartbeat=False):
        """Force close connection"""
        self._force_close = True
        if self._waiter:
            self._waiter.cancel()
        if self.transport is not None:
            if send_last_heartbeat:
                self.transport.write(b"\r\n")
            self.transport.close()
            self.transport = None

    def log_access(self, request, response, time):
        if self.access_logger is not None:
            self.access_logger.log(request, response, time)

    def log_debug(self, *args, **kw):
        if self.debug:
            self.logger.debug(*args, **kw)

    def log_exception(self, *args, **kw):
        self.logger.exception(*args, **kw)

    def _process_keepalive(self):
        if self._force_close or not self._keepalive:
            return

        next = self._keepalive_time + self._keepalive_timeout

        # handler in idle state
        if self._waiter:
            if self._loop.time() > next:
                self.force_close(send_last_heartbeat=True)
                return

        # not all request handlers are done,
        # reschedule itself to next second
        self._keepalive_handle = self._loop.call_later(
            self.KEEPALIVE_RESCHEDULE_DELAY, self._process_keepalive)

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

    async def start(self):
        """Process incoming request.

        It reads request line, request headers and request payload, then
        calls handle_request() method. Subclass has to override
        handle_request(). start() handles various exceptions in request
        or response handling. Connection is being closed always unless
        keep_alive(True) specified.
        """
        loop = self._loop
        handler = self._task_handler
        manager = self._manager
        keepalive_timeout = self._keepalive_timeout

        while not self._force_close:
            if not self._messages:
                try:
                    # wait for next request
                    self._waiter = loop.create_future()
                    await self._waiter
                except asyncio.CancelledError:
                    break
                finally:
                    self._waiter = None

            message, payload = self._messages.popleft()

            if self.access_log:
                now = loop.time()

            manager.requests_count += 1
            writer = StreamWriter(self, self.transport, loop)
            request = self._request_factory(
                message, payload, self, writer, handler)
            try:
                try:
                    resp = await self._request_handler(request)
                except HTTPException as exc:
                    resp = exc
                except asyncio.CancelledError:
                    self.log_debug('Ignored premature client disconnection')
                    break
                except asyncio.TimeoutError:
                    self.log_debug('Request handler timed out.')
                    resp = self.handle_error(request, 504)
                except Exception as exc:
                    resp = self.handle_error(request, 500, exc)
                else:
                    # Deprecation warning (See #2415)
                    if isinstance(resp, HTTPException):
                        warnings.warn(
                            "returning HTTPException object is deprecated "
                            "(#2415) and will be removed, "
                            "please raise the exception instead",
                            DeprecationWarning)

                await resp.prepare(request)
                await resp.write_eof()

                # notify server about keep-alive
                self._keepalive = resp.keep_alive

                # log access
                if self.access_log:
                    self.log_access(request, resp, loop.time() - now)

                # check payload
                if not payload.is_eof():
                    lingering_time = self._lingering_time
                    if not self._force_close and lingering_time:
                        self.log_debug(
                            'Start lingering close timer for %s sec.',
                            lingering_time)

                        now = loop.time()
                        end_t = now + lingering_time

                        with suppress(
                                asyncio.TimeoutError, asyncio.CancelledError):
                            while not payload.is_eof() and now < end_t:
                                timeout = min(end_t - now, lingering_time)
                                with CeilTimeout(timeout, loop=loop):
                                    # read and ignore
                                    await payload.readany()
                                now = loop.time()

                    # if payload still uncompleted
                    if not payload.is_eof() and not self._force_close:
                        self.log_debug('Uncompleted request.')
                        self.close()

            except asyncio.CancelledError:
                self.log_debug('Ignored premature client disconnection ')
                break
            except RuntimeError as exc:
                if self.debug:
                    self.log_exception(
                        'Unhandled runtime exception', exc_info=exc)
                self.force_close()
            except Exception as exc:
                self.log_exception('Unhandled exception', exc_info=exc)
                self.force_close()
            finally:
                if self.transport is None:
                    self.log_debug('Ignored premature client disconnection.')
                elif not self._force_close:
                    if self._keepalive and not self._close:
                        # start keep-alive timer
                        if keepalive_timeout is not None:
                            now = self._loop.time()
                            self._keepalive_time = now
                            if self._keepalive_handle is None:
                                self._keepalive_handle = loop.call_at(
                                    now + keepalive_timeout,
                                    self._process_keepalive)
                    else:
                        break

        # remove handler, close transport if no handlers left
        if not self._force_close:
            self._task_handler = None
            if self.transport is not None and self._error_handler is None:
                self.transport.close()

    def handle_error(self, request, status=500, exc=None, message=None):
        """Handle errors.

        Returns HTTP response with specific status code. Logs additional
        information. It always closes current connection."""
        self.log_exception("Error handling request", exc_info=exc)

        if status == 500:
            msg = "<h1>500 Internal Server Error</h1>"
            if self.debug:
                with suppress(Exception):
                    tb = traceback.format_exc()
                    tb = html_escape(tb)
                    msg += '<br><h2>Traceback:</h2>\n<pre>'
                    msg += tb
                    msg += '</pre>'
            else:
                msg += "Server got itself in trouble"
                msg = ("<html><head><title>500 Internal Server Error</title>"
                       "</head><body>" + msg + "</body></html>")
        else:
            msg = message

        resp = Response(status=status, text=msg, content_type='text/html')
        resp.force_close()

        # some data already got sent, connection is broken
        if request.writer.output_size > 0 or self.transport is None:
            self.force_close()

        return resp

    async def handle_parse_error(self, writer, status, exc=None, message=None):
        request = BaseRequest(
            ERROR, EMPTY_PAYLOAD,
            self, writer, None, self._loop)

        resp = self.handle_error(request, status, exc, message)
        await resp.prepare(request)
        await resp.write_eof()

        if self.transport is not None:
            self.transport.close()

        self._error_handler = None
