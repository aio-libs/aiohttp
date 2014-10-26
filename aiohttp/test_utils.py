"""Utilities shared by tests."""

import cgi
import contextlib
import gc
import email.parser
import http.server
import json
import logging
import io
import os
import re
import ssl
import sys
import threading
import traceback
import urllib.parse

import asyncio
import aiohttp
from aiohttp import server
from aiohttp import helpers


def run_briefly(loop):
    @asyncio.coroutine
    def once():
        pass
    t = asyncio.Task(once(), loop=loop)
    loop.run_until_complete(t)


@contextlib.contextmanager
def run_server(loop, *, listen_addr=('127.0.0.1', 0),
               use_ssl=False, router=None):
    properties = {}
    transports = []

    class HttpRequestHandler:

        def __init__(self, addr):
            if isinstance(addr, tuple):
                host, port = addr
                self.host = host
                self.port = port
            else:
                self.host = host = 'localhost'
                self.port = port = 0
            self.address = addr
            self._url = '{}://{}:{}'.format(
                'https' if use_ssl else 'http', host, port)

        def __getitem__(self, key):
            return properties[key]

        def __setitem__(self, key, value):
            properties[key] = value

        def url(self, *suffix):
            return urllib.parse.urljoin(
                self._url, '/'.join(str(s) for s in suffix))

    class TestHttpServer(server.ServerHttpProtocol):

        def connection_made(self, transport):
            transports.append(transport)

            super().connection_made(transport)

        def handle_request(self, message, payload):
            if properties.get('close', False):
                return

            if properties.get('noresponse', False):
                yield from asyncio.sleep(99999)

            for hdr, val in message.headers.items(getall=True):
                if (hdr == 'EXPECT') and (val == '100-continue'):
                    self.transport.write(b'HTTP/1.0 100 Continue\r\n\r\n')
                    break

            if router is not None:
                body = yield from payload.read()

                rob = router(
                    self, properties, self.transport, message, body)
                rob.dispatch()

            else:
                response = aiohttp.Response(self.writer, 200, message.version)

                text = b'Test message'
                response.add_header('Content-type', 'text/plain')
                response.add_header('Content-length', str(len(text)))
                response.send_headers()
                response.write(text)
                response.write_eof()

    if use_ssl:
        here = os.path.join(os.path.dirname(__file__), '..', 'tests')
        keyfile = os.path.join(here, 'sample.key')
        certfile = os.path.join(here, 'sample.crt')
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sslcontext.load_cert_chain(certfile, keyfile)
    else:
        sslcontext = None

    def run(loop, fut):
        thread_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(thread_loop)

        if isinstance(listen_addr, tuple):
            host, port = listen_addr
            server_coroutine = thread_loop.create_server(
                lambda: TestHttpServer(keep_alive=0.5),
                host, port, ssl=sslcontext)
        else:
            try:
                os.unlink(listen_addr)
            except FileNotFoundError:
                pass
            server_coroutine = thread_loop.create_unix_server(
                lambda: TestHttpServer(keep_alive=0.5),
                listen_addr, ssl=sslcontext)
        server = thread_loop.run_until_complete(server_coroutine)

        waiter = asyncio.Future(loop=thread_loop)
        loop.call_soon_threadsafe(
            fut.set_result, (thread_loop, waiter,
                             server.sockets[0].getsockname()))

        try:
            thread_loop.run_until_complete(waiter)
        finally:
            # call pending connection_made if present
            run_briefly(thread_loop)

            # close opened transports
            for tr in transports:
                tr.close()

            run_briefly(thread_loop)  # call close callbacks

            server.close()
            thread_loop.stop()
            thread_loop.close()
            gc.collect()

    fut = asyncio.Future(loop=loop)
    server_thread = threading.Thread(target=run, args=(loop, fut))
    server_thread.start()

    thread_loop, waiter, addr = loop.run_until_complete(fut)
    try:
        yield HttpRequestHandler(addr)
    finally:
        thread_loop.call_soon_threadsafe(waiter.set_result, None)
        server_thread.join()


class Router:

    _response_version = "1.1"
    _responses = http.server.BaseHTTPRequestHandler.responses

    def __init__(self, srv, props, transport, message, payload):
        # headers
        self._headers = http.client.HTTPMessage()
        for hdr, val in message.headers.items(getall=True):
            self._headers.add_header(hdr, val)

        self._srv = srv
        self._props = props
        self._transport = transport
        self._method = message.method
        self._uri = message.path
        self._version = message.version
        self._compression = message.compression
        self._body = payload

        url = urllib.parse.urlsplit(self._uri)
        self._path = url.path
        self._query = url.query

    @staticmethod
    def define(rmatch):
        def wrapper(fn):
            f_locals = sys._getframe(1).f_locals
            mapping = f_locals.setdefault('_mapping', [])
            mapping.append((re.compile(rmatch), fn.__name__))
            return fn

        return wrapper

    def dispatch(self):  # pragma: no cover
        for route, fn in self._mapping:
            match = route.match(self._path)
            if match is not None:
                try:
                    return getattr(self, fn)(match)
                except Exception:
                    out = io.StringIO()
                    traceback.print_exc(file=out)
                    self._response(500, out.getvalue())

                return

        return self._response(self._start_response(404))

    def _start_response(self, code):
        return aiohttp.Response(self._srv.writer, code)

    def _response(self, response, body=None,
                  headers=None, chunked=False, write_body=None):
        r_headers = {}
        for key, val in self._headers.items():
            key = '-'.join(p.capitalize() for p in key.split('-'))
            r_headers[key] = val

        encoding = self._headers.get('content-encoding', '').lower()
        if 'gzip' in encoding:  # pragma: no cover
            cmod = 'gzip'
        elif 'deflate' in encoding:
            cmod = 'deflate'
        else:
            cmod = ''

        resp = {
            'method': self._method,
            'version': '%s.%s' % self._version,
            'path': self._uri,
            'headers': r_headers,
            'origin': self._transport.get_extra_info('addr', ' ')[0],
            'query': self._query,
            'form': {},
            'compression': cmod,
            'multipart-data': []
        }
        if body:  # pragma: no cover
            resp['content'] = body
        else:
            resp['content'] = self._body.decode('utf-8', 'ignore')

        ct = self._headers.get('content-type', '').lower()

        # application/x-www-form-urlencoded
        if ct == 'application/x-www-form-urlencoded':
            resp['form'] = urllib.parse.parse_qs(self._body.decode('latin1'))

        # multipart/form-data
        elif ct.startswith('multipart/form-data'):  # pragma: no cover
            out = io.BytesIO()
            for key, val in self._headers.items():
                out.write(bytes('{}: {}\r\n'.format(key, val), 'latin1'))

            out.write(b'\r\n')
            out.write(self._body)
            out.write(b'\r\n')
            out.seek(0)

            message = email.parser.BytesParser().parse(out)
            if message.is_multipart():
                for msg in message.get_payload():
                    if msg.is_multipart():
                        logging.warning('multipart msg is not expected')
                    else:
                        key, params = cgi.parse_header(
                            msg.get('content-disposition', ''))
                        params['data'] = msg.get_payload()
                        params['content-type'] = msg.get_content_type()
                        cte = msg.get('content-transfer-encoding')
                        if cte is not None:
                            resp['content-transfer-encoding'] = cte
                        resp['multipart-data'].append(params)
        body = json.dumps(resp, indent=4, sort_keys=True)

        # default headers
        hdrs = [('Connection', 'close'),
                ('Content-Type', 'application/json')]
        if chunked:
            hdrs.append(('Transfer-Encoding', 'chunked'))
        else:
            hdrs.append(('Content-Length', str(len(body))))

        # extra headers
        if headers:
            hdrs.extend(headers.items())

        if chunked:
            response.force_chunked()

        # headers
        response.add_headers(*hdrs)
        response.send_headers()

        # write payload
        if write_body:
            try:
                write_body(response, body)
            except:
                return
        else:
            response.write(helpers.str_to_bytes(body))

        response.write_eof()

        # keep-alive
        if response.keep_alive():
            self._srv.keep_alive(True)
