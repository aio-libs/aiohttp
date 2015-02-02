"""simple http server."""

__all__ = ['ServerHttpProtocol']

import asyncio
import http.server
import time
import traceback
import socket

from html import escape as html_escape

import aiohttp
from aiohttp import errors, streams, helpers
from aiohttp.log import server_logger, access_logger


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

ACCESS_LOG_FORMAT = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"')


class ServerHttpProtocol(aiohttp.StreamProtocol):
    """Simple http protocol implementation.

    ServerHttpProtocol handles incoming http request. It reads request line,
    request headers and request payload and calls handle_request() method.
    By default it always returns with 404 response.

    ServerHttpProtocol handles errors in incoming request, like bad
    status line, bad headers or incomplete payload. If any error occurs,
    connection gets closed.

    :param keep_alive: number of seconds before closing keep-alive connection
    :type keep_alive: int or None

    :param int timeout: slow request timeout

    :param bool tcp_keepalive: TCP socket keep-alive flag

    :param allowed_methods: (optional) List of allowed request methods.
                            Set to empty list to allow all methods.
    :type allowed_methods: tuple

    :param bool debug: enable debug mode

    :param logger: custom logger object
    :type logger: aiohttp.log.server_logger

    :param access_log: custom logging object
    :type access_log: aiohttp.log.server_logger

    :param str access_log_format: access log format string

    :param loop: Optional event loop
    """
    _request_count = 0
    _request_handler = None
    _reading_request = False
    _keep_alive = False  # keep transport open
    _keep_alive_handle = None  # keep alive timer handle
    _timeout_handle = None  # slow request timer handle

    _request_parser = aiohttp.HttpRequestParser()  # default request parser

    def __init__(self, *, loop=None,
                 keep_alive=75,  # NGINX default value is 75 secs
                 timeout=15,
                 tcp_keepalive=True,
                 allowed_methods=(),
                 logger=server_logger,
                 access_log=access_logger,
                 access_log_format=ACCESS_LOG_FORMAT,
                 host="",
                 port=0,
                 debug=False,
                 log=None,
                 **kwargs):
        super().__init__(
            loop=loop,
            disconnect_error=errors.ClientDisconnectedError, **kwargs)

        self._keep_alive_period = keep_alive  # number of seconds to keep alive
        self._timeout = timeout  # slow request timeout
        self._tcp_keepalive = tcp_keepalive  # use detection of broken socket
        self._request_prefix = aiohttp.HttpPrefixParser(allowed_methods)
        self._loop = loop if loop is not None else asyncio.get_event_loop()

        self.host = host
        self.port = port
        self.logger = log or logger
        self.debug = debug
        self.access_log = access_log
        self.access_log_format = access_log_format

    @property
    def keep_alive_timeout(self):
        return self._keep_alive_period

    def closing(self):
        """Worker process is about to exit, we need cleanup everything and
        stop accepting requests. It is especially important for keep-alive
        connections."""
        self._keep_alive = False
        self._keep_alive_period = None

        if (not self._reading_request and self.transport is not None):
            if self._request_handler:
                self._request_handler.cancel()
                self._request_handler = None

            self.transport.close()
            self.transport = None

    def connection_made(self, transport):
        super().connection_made(transport)

        if self._tcp_keepalive and hasattr(socket, 'SO_KEEPALIVE'):
            sock = transport.get_extra_info('socket')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        self._request_handler = asyncio.async(self.start(), loop=self._loop)

        # start slow request timer
        if self._timeout:
            self._timeout_handle = self._loop.call_later(
                self._timeout, self.cancel_slow_request)

    def connection_lost(self, exc):
        super().connection_lost(exc)

        if self._request_handler is not None:
            self._request_handler.cancel()
            self._request_handler = None
        if self._keep_alive_handle is not None:
            self._keep_alive_handle.cancel()
            self._keep_alive_handle = None
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()
            self._timeout_handle = None

    def keep_alive(self, val):
        """Set keep-alive connection mode.

        :param bool val: new state.
        """
        self._keep_alive = val

    def log_access(self, message, environ, response, time):
        if self.access_log and self.access_log_format:
            try:
                environ = environ if environ is not None else {}
                atoms = helpers.SafeAtoms(
                    helpers.atoms(
                        message, environ, response, self.transport, time),
                    getattr(message, 'headers', None),
                    getattr(response, 'headers', None))
                self.access_log.info(self.access_log_format % atoms)
            except:
                self.logger.error(traceback.format_exc())

    def log_debug(self, *args, **kw):
        if self.debug:
            self.logger.debug(*args, **kw)

    def log_exception(self, *args, **kw):
        self.logger.exception(*args, **kw)

    def cancel_slow_request(self):
        if self._request_handler is not None:
            self._request_handler.cancel()
            self._request_handler = None

        if self.transport is not None:
            self.transport.close()

        self.log_debug('Close slow request.')

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

        while True:
            message = None
            self._keep_alive = False
            self._request_count += 1
            self._reading_request = False

            payload = None
            try:
                prefix = reader.set_parser(self._request_prefix)
                yield from prefix.read()
                self._reading_request = True

                # stop keep-alive timer
                if self._keep_alive_handle is not None:
                    self._keep_alive_handle.cancel()
                    self._keep_alive_handle = None

                # start slow request timer
                if self._timeout and self._timeout_handle is None:
                    self._timeout_handle = self._loop.call_later(
                        self._timeout, self.cancel_slow_request)

                # read request headers
                httpstream = reader.set_parser(self._request_parser)
                message = yield from httpstream.read()

                # cancel slow request timer
                if self._timeout_handle is not None:
                    self._timeout_handle.cancel()
                    self._timeout_handle = None

                payload = streams.FlowControlStreamReader(
                    reader, loop=self._loop)
                reader.set_parser(aiohttp.HttpPayloadParser(message), payload)

                handler = self.handle_request(message, payload)
                if (asyncio.iscoroutine(handler) or
                        isinstance(handler, asyncio.Future)):
                    yield from handler

            except (asyncio.CancelledError,
                    errors.ClientDisconnectedError):
                self.log_debug('Ignored premature client disconnection.')
                break
            except errors.HttpProcessingError as exc:
                if self.transport is not None:
                    yield from self.handle_error(exc.code, message,
                                                 None, exc, exc.headers)
            except Exception as exc:
                yield from self.handle_error(500, message, None, exc)
            finally:
                if self.transport is None:
                    self.log_debug('Ignored premature client disconnection.')
                    break

                if payload and not payload.is_eof():
                    self.log_debug('Uncompleted request.')
                    self._request_handler = None
                    self.transport.close()
                    break
                else:
                    reader.unset_parser()

                if self._request_handler:
                    if self._keep_alive and self._keep_alive_period:
                        self.log_debug(
                            'Start keep-alive timer for %s sec.',
                            self._keep_alive_period)
                        self._keep_alive_handle = self._loop.call_later(
                            self._keep_alive_period, self.transport.close)
                    else:
                        self.log_debug('Close client connection.')
                        self._request_handler = None
                        self.transport.close()
                        break
                else:
                    break

    def handle_error(self, status=500,
                     message=None, payload=None, exc=None, headers=None):
        """Handle errors.

        Returns http response with specific status code. Logs additional
        information. It always closes current connection."""
        now = time.time()
        try:
            if self._request_handler is None:
                # client has been disconnected during writing.
                return ()

            if status == 500:
                self.log_exception("Error handling request")

            try:
                reason, msg = RESPONSES[status]
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
            response.add_headers(
                ('CONTENT-TYPE', 'text/html; charset=utf-8'),
                ('CONTENT-LENGTH', str(len(html))))
            if headers is not None:
                response.add_headers(*headers)
            response.send_headers()

            response.write(html)
            drain = response.write_eof()

            self.log_access(message, None, response, time.time() - now)
            return drain
        finally:
            self.keep_alive(False)

    def handle_request(self, message, payload):
        """Handle a single http request.

        Subclass should override this method. By default it always
        returns 404 response.

        :param message: Request headers
        :type message: aiohttp.protocol.HttpRequestParser
        :param payload: Request payload
        :type payload: aiohttp.streams.FlowControlStreamReader
        """
        now = time.time()
        response = aiohttp.Response(
            self.writer, 404, http_version=message.version, close=True)

        body = b'Page Not Found!'

        response.add_headers(
            ('CONTENT-TYPE', 'text/plain'),
            ('CONTENT-LENGTH', str(len(body))))
        response.send_headers()
        response.write(body)
        drain = response.write_eof()

        self.keep_alive(False)
        self.log_access(message, None, response, time.time() - now)

        return drain
