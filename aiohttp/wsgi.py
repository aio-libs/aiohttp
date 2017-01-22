"""wsgi server.

TODO:
  * proxy protocol
  * x-forward security
  * wsgi file support (os.sendfile)
"""

import asyncio
import inspect
import io
import os
import socket
import sys
from urllib.parse import urlsplit

import aiohttp
from aiohttp import hdrs, server

__all__ = ('WSGIServerHttpProtocol',)


class WSGIServerHttpProtocol(server.ServerHttpProtocol):
    """HTTP Server that implements the Python WSGI protocol.

    It uses 'wsgi.async' of 'True'. 'wsgi.input' can behave differently
    depends on 'readpayload' constructor parameter. If readpayload is set to
    True, wsgi server reads all incoming data into BytesIO object and
    sends it as 'wsgi.input' environ var. If readpayload is set to false
    'wsgi.input' is a StreamReader and application should read incoming
    data with "yield from environ['wsgi.input'].read()". It defaults to False.
    """

    SCRIPT_NAME = os.environ.get('SCRIPT_NAME', '')

    def __init__(self, app, readpayload=False, is_ssl=False, *args, **kw):
        super().__init__(*args, **kw)

        self.wsgi = app
        self.is_ssl = is_ssl
        self.readpayload = readpayload

    def create_wsgi_response(self, message):
        return WsgiResponse(self.writer, message)

    def create_wsgi_environ(self, message, payload):
        uri_parts = urlsplit(message.path)

        environ = {
            'wsgi.input': payload,
            'wsgi.errors': sys.stderr,
            'wsgi.version': (1, 0),
            'wsgi.async': True,
            'wsgi.multithread': False,
            'wsgi.multiprocess': False,
            'wsgi.run_once': False,
            'wsgi.file_wrapper': FileWrapper,
            'SERVER_SOFTWARE': aiohttp.HttpMessage.SERVER_SOFTWARE,
            'REQUEST_METHOD': message.method,
            'QUERY_STRING': uri_parts.query or '',
            'RAW_URI': message.path,
            'SERVER_PROTOCOL': 'HTTP/%s.%s' % message.version
        }

        script_name = self.SCRIPT_NAME

        for hdr_name, hdr_value in message.headers.items():
            hdr_name = hdr_name.upper()
            if hdr_name == 'SCRIPT_NAME':
                script_name = hdr_value
            elif hdr_name == 'CONTENT-TYPE':
                environ['CONTENT_TYPE'] = hdr_value
                continue
            elif hdr_name == 'CONTENT-LENGTH':
                environ['CONTENT_LENGTH'] = hdr_value
                continue

            key = 'HTTP_%s' % hdr_name.replace('-', '_')
            if key in environ:
                hdr_value = '%s,%s' % (environ[key], hdr_value)

            environ[key] = hdr_value

        url_scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if url_scheme is None:
            url_scheme = 'https' if self.is_ssl else 'http'
        environ['wsgi.url_scheme'] = url_scheme

        # authors should be aware that REMOTE_HOST and REMOTE_ADDR
        # may not qualify the remote addr
        # also SERVER_PORT variable MUST be set to the TCP/IP port number on
        # which this request is received from the client.
        # http://www.ietf.org/rfc/rfc3875

        family = self.transport.get_extra_info('socket').family
        if family in (socket.AF_INET, socket.AF_INET6):
            peername = self.transport.get_extra_info('peername')
            environ['REMOTE_ADDR'] = peername[0]
            environ['REMOTE_PORT'] = str(peername[1])
            http_host = message.headers.get("HOST", None)
            if http_host:
                hostport = http_host.split(":")
                environ['SERVER_NAME'] = hostport[0]
                if len(hostport) > 1:
                    environ['SERVER_PORT'] = str(hostport[1])
                else:
                    environ['SERVER_PORT'] = '80'
            else:
                # SERVER_NAME should be set to value of Host header, but this
                # header is not required. In this case we shoud set it to local
                # address of socket
                sockname = self.transport.get_extra_info('sockname')
                environ['SERVER_NAME'] = sockname[0]
                environ['SERVER_PORT'] = str(sockname[1])
        else:
            # We are behind reverse proxy, so get all vars from headers
            for header in ('REMOTE_ADDR', 'REMOTE_PORT',
                           'SERVER_NAME', 'SERVER_PORT'):
                environ[header] = message.headers.get(header, '')

        path_info = uri_parts.path
        if script_name:
            path_info = path_info.split(script_name, 1)[-1]

        environ['PATH_INFO'] = path_info
        environ['SCRIPT_NAME'] = script_name

        environ['async.reader'] = self.reader
        environ['async.writer'] = self.writer

        return environ

    @asyncio.coroutine
    def handle_request(self, message, payload):
        """Handle a single HTTP request"""
        now = self._loop.time()

        if self.readpayload:
            wsgiinput = io.BytesIO()
            wsgiinput.write((yield from payload.read()))
            wsgiinput.seek(0)
            payload = wsgiinput

        environ = self.create_wsgi_environ(message, payload)
        response = self.create_wsgi_response(message)

        riter = self.wsgi(environ, response.start_response)
        if isinstance(riter, asyncio.Future) or inspect.isgenerator(riter):
            riter = yield from riter

        resp = response.response
        try:
            for item in riter:
                if isinstance(item, asyncio.Future):
                    item = yield from item
                yield from resp.write(item)

            yield from resp.write_eof()
        finally:
            if hasattr(riter, 'close'):
                riter.close()

        if resp.keep_alive():
            self.keep_alive(True)

        self.log_access(
            message, environ, response.response, self._loop.time() - now)


class FileWrapper:
    """Custom file wrapper."""

    def __init__(self, fobj, chunk_size=8192):
        self.fobj = fobj
        self.chunk_size = chunk_size
        if hasattr(fobj, 'close'):
            self.close = fobj.close

    def __iter__(self):
        return self

    def __next__(self):
        data = self.fobj.read(self.chunk_size)
        if data:
            return data
        raise StopIteration


class WsgiResponse:
    """Implementation of start_response() callable as specified by PEP 3333"""

    status = None

    HOP_HEADERS = {
        hdrs.CONNECTION,
        hdrs.KEEP_ALIVE,
        hdrs.PROXY_AUTHENTICATE,
        hdrs.PROXY_AUTHORIZATION,
        hdrs.TE,
        hdrs.TRAILER,
        hdrs.TRANSFER_ENCODING,
        hdrs.UPGRADE,
    }

    def __init__(self, writer, message):
        self.writer = writer
        self.message = message

    def start_response(self, status, headers, exc_info=None):
        if exc_info:
            try:
                if self.status:
                    raise exc_info[1]
            finally:
                exc_info = None

        status_code = int(status.split(' ', 1)[0])

        self.status = status
        resp = self.response = aiohttp.Response(
            self.writer, status_code,
            self.message.version, self.message.should_close)
        resp.HOP_HEADERS = self.HOP_HEADERS
        for name, value in headers:
            resp.add_header(name, value)

        if resp.has_chunked_hdr:
            resp.enable_chunked_encoding()

        # send headers immediately for websocket connection
        if status_code == 101 and resp.upgrade and resp.websocket:
            resp.send_headers()
        else:
            resp._send_headers = True
        return self.response.write
