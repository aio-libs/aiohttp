"""simple HTTP server."""

import asyncio
import http.server
import socket
import traceback
import warnings
from contextlib import suppress
from html import escape as html_escape

import aiohttp
from aiohttp import errors, hdrs, helpers, streams
from aiohttp.helpers import Timeout, _get_kwarg, ensure_future
from aiohttp.log import access_logger, server_logger

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

EMPTY_PAYLOAD = streams.EmptyStreamReader()


class ServerHttpProtocol(aiohttp.StreamProtocol):
    """Simple HTTP protocol implementation.

    ServerHttpProtocol handles incoming HTTP request. It reads request line,
    request headers and request payload and calls handle_request() method.
    By default it always returns with 404 response.

    ServerHttpProtocol handles errors in incoming request, like bad
    status line, bad headers or incomplete payload. If any error occurs,
    connection gets closed.

    :param keepalive_timeout: number of seconds before closing
                              keep-alive connection
    :type keepalive_timeout: int or None

    :param bool tcp_keepalive: TCP keep-alive is on, default is on

    :param int slow_request_timeout: slow request timeout

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
    _request_handler = None
    _reading_request = False
    _keepalive = False  # keep transport open

    def __init__(self, *, loop=None,
                 keepalive_timeout=75,  # NGINX default value is 75 secs
                 tcp_keepalive=True,
                 slow_request_timeout=0,
                 logger=server_logger,
                 access_log=access_logger,
                 access_log_format=helpers.AccessLogger.LOG_FORMAT,
                 debug=False,
                 max_line_size=8190,
                 max_headers=32768,
                 max_field_size=8190,
                 **kwargs):

        # process deprecated params
        logger = _get_kwarg(kwargs, 'log', 'logger', logger)

        tcp_keepalive = _get_kwarg(kwargs, 'keep_alive_on',
                                   'tcp_keepalive', tcp_keepalive)

        keepalive_timeout = _get_kwarg(kwargs, 'keep_alive',
                                       'keepalive_timeout', keepalive_timeout)

        slow_request_timeout = _get_kwarg(kwargs, 'timeout',
                                          'slow_request_timeout',
                                          slow_request_timeout)

        super().__init__(
            loop=loop,
            disconnect_error=errors.ClientDisconnectedError, **kwargs)

        self._tcp_keepalive = tcp_keepalive
        self._keepalive_timeout = keepalive_timeout
        self._slow_request_timeout = slow_request_timeout
        self._loop = loop if loop is not None else asyncio.get_event_loop()

        self._request_prefix = aiohttp.HttpPrefixParser()
        self._request_parser = aiohttp.HttpRequestParser(
            max_line_size=max_line_size,
            max_field_size=max_field_size,
            max_headers=max_headers)

        self.logger = logger
        self.debug = debug
        self.access_log = access_log
        if access_log:
            self.access_logger = helpers.AccessLogger(access_log,
                                                      access_log_format)
        else:
            self.access_logger = None
        self._closing = False

    @property
    def keep_alive_timeout(self):
        warnings.warn("Use keepalive_timeout property instead",
                      DeprecationWarning,
                      stacklevel=2)
        return self._keepalive_timeout

    @property
    def keepalive_timeout(self):
        return self._keepalive_timeout

    @asyncio.coroutine
    def shutdown(self, timeout=15.0):
        """Worker process is about to exit, we need cleanup everything and
        stop accepting requests. It is especially important for keep-alive
        connections."""
        if self._request_handler is None:
            return
        self._closing = True

        if timeout:
            canceller = self._loop.call_later(timeout,
                                              self._request_handler.cancel)
            with suppress(asyncio.CancelledError):
                yield from self._request_handler
            canceller.cancel()
        else:
            self._request_handler.cancel()

    def connection_made(self, transport):
        super().connection_made(transport)

        self._request_handler = ensure_future(self.start(), loop=self._loop)

        if self._tcp_keepalive:
            tcp_keepalive(self, transport)

    def connection_lost(self, exc):
        super().connection_lost(exc)

        self._closing = True
        if self._request_handler is not None:
            self._request_handler.cancel()

    def data_received(self, data):
        super().data_received(data)

        # reading request
        if not self._reading_request:
            self._reading_request = True

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

    @asyncio.coroutine
    def start(self):
        """Start processing of incoming requests.

        It reads request line, request headers and request payload, then
        calls handle_request() method. Subclass has to override
        handle_request(). start() handles various exceptions in request
        or response handling. Connection is being closed always unless
        keep_alive(True) specified.
        """
        reader = self.reader

        try:
            while not self._closing:
                message = None
                self._keepalive = False
                self._request_count += 1
                self._reading_request = False

                payload = None
                with Timeout(max(self._slow_request_timeout,
                                 self._keepalive_timeout),
                             loop=self._loop):
                    # read HTTP request method
                    prefix = reader.set_parser(self._request_prefix)
                    yield from prefix.read()

                    # start reading request
                    self._reading_request = True

                    # start slow request timer
                    # read request headers
                    httpstream = reader.set_parser(self._request_parser)
                    message = yield from httpstream.read()

                # request may not have payload
                try:
                    content_length = int(
                        message.headers.get(hdrs.CONTENT_LENGTH, 0))
                except ValueError:
                    raise errors.InvalidHeader(hdrs.CONTENT_LENGTH) from None

                if (content_length > 0 or
                    message.method == 'CONNECT' or
                    hdrs.SEC_WEBSOCKET_KEY1 in message.headers or
                    'chunked' in message.headers.get(
                        hdrs.TRANSFER_ENCODING, '')):
                    payload = streams.FlowControlStreamReader(
                        reader, loop=self._loop)
                    reader.set_parser(
                        aiohttp.HttpPayloadParser(message), payload)
                else:
                    payload = EMPTY_PAYLOAD

                yield from self.handle_request(message, payload)

                if payload and not payload.is_eof():
                    self.log_debug('Uncompleted request.')
                    self._closing = True
                else:
                    reader.unset_parser()
                    if not self._keepalive or not self._keepalive_timeout:
                        self._closing = True

        except asyncio.CancelledError:
            self.log_debug(
                'Request handler cancelled.')
            return
        except asyncio.TimeoutError:
            self.log_debug(
                'Request handler timed out.')
            return
        except errors.ClientDisconnectedError:
            self.log_debug(
                'Ignored premature client disconnection #1.')
            return
        except errors.HttpProcessingError as exc:
            yield from self.handle_error(exc.code, message,
                                         None, exc, exc.headers,
                                         exc.message)
        except Exception as exc:
            yield from self.handle_error(500, message, None, exc)
        finally:
            self._request_handler = None
            if self.transport is None:
                self.log_debug(
                    'Ignored premature client disconnection #2.')
            else:
                self.transport.close()

    def handle_error(self, status=500, message=None,
                     payload=None, exc=None, headers=None, reason=None):
        """Handle errors.

        Returns HTTP response with specific status code. Logs additional
        information. It always closes current connection."""
        now = self._loop.time()
        try:
            if self.transport is None:
                # client has been disconnected during writing.
                return ()

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

            response = aiohttp.Response(self.writer, status, close=True)
            response.add_header(hdrs.CONTENT_TYPE, 'text/html; charset=utf-8')
            response.add_header(hdrs.CONTENT_LENGTH, str(len(html)))
            if headers is not None:
                for name, value in headers:
                    response.add_header(name, value)
            response.send_headers()

            response.write(html)
            # disable CORK, enable NODELAY if needed
            self.writer.set_tcp_nodelay(True)
            drain = response.write_eof()

            self.log_access(message, None, response, self._loop.time() - now)
            return drain
        finally:
            self.keep_alive(False)

    def handle_request(self, message, payload):
        """Handle a single HTTP request.

        Subclass should override this method. By default it always
        returns 404 response.

        :param message: Request headers
        :type message: aiohttp.protocol.HttpRequestParser
        :param payload: Request payload
        :type payload: aiohttp.streams.FlowControlStreamReader
        """
        now = self._loop.time()
        response = aiohttp.Response(
            self.writer, 404, http_version=message.version, close=True)

        body = b'Page Not Found!'

        response.add_header(hdrs.CONTENT_TYPE, 'text/plain')
        response.add_header(hdrs.CONTENT_LENGTH, str(len(body)))
        response.send_headers()
        response.write(body)
        drain = response.write_eof()

        self.keep_alive(False)
        self.log_access(message, None, response, self._loop.time() - now)

        return drain
