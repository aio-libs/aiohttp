#!/usr/bin/env python3
"""Simple server written using an event loop."""

import argparse
import asyncio
import logging
import os
import sys

import aiohttp
import aiohttp.server

try:
    import ssl
except ImportError:  # pragma: no cover
    ssl = None


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

    @asyncio.coroutine
    def handle_request(self, message, payload):
        print('method = {!r}; path = {!r}; version = {!r}'.format(
            message.method, message.path, message.version))

        path = message.path

        if (not (path.isprintable() and path.startswith('/')) or '/.' in path):
            print('bad path', repr(path))
            path = None
        else:
            path = '.' + path
            if not os.path.exists(path):
                print('no file', repr(path))
                path = None
            else:
                isdir = os.path.isdir(path)

        if not path:
            raise aiohttp.HttpProcessingError(code=404)

        for hdr, val in message.headers.items():
            print(hdr, val)

        if isdir and not path.endswith('/'):
            path = path + '/'
            raise aiohttp.HttpProcessingError(
                code=302, headers=(('URI', path), ('Location', path)))

        response = aiohttp.Response(
            self.writer, 200, http_version=message.version)
        response.add_header('Transfer-Encoding', 'chunked')

        # content encoding
        accept_encoding = message.headers.get('accept-encoding', '').lower()
        if 'deflate' in accept_encoding:
            response.add_header('Content-Encoding', 'deflate')
            response.add_compression_filter('deflate')
        elif 'gzip' in accept_encoding:
            response.add_header('Content-Encoding', 'gzip')
            response.add_compression_filter('gzip')

        response.add_chunking_filter(1025)

        if isdir:
            response.add_header('Content-type', 'text/html')
            response.send_headers()

            response.write(b'<ul>\r\n')
            for name in sorted(os.listdir(path)):
                if name.isprintable() and not name.startswith('.'):
                    try:
                        bname = name.encode('ascii')
                    except UnicodeError:
                        pass
                    else:
                        if os.path.isdir(os.path.join(path, name)):
                            response.write(b'<li><a href="' + bname +
                                           b'/">' + bname + b'/</a></li>\r\n')
                        else:
                            response.write(b'<li><a href="' + bname +
                                           b'">' + bname + b'</a></li>\r\n')
            response.write(b'</ul>')
        else:
            response.add_header('Content-type', 'text/plain')
            response.send_headers()

            try:
                with open(path, 'rb') as fp:
                    chunk = fp.read(8192)
                    while chunk:
                        response.write(chunk)
                        chunk = fp.read(8192)
            except OSError:
                response.write(b'Cannot open')

        yield from response.write_eof()
        if response.keep_alive():
            self.keep_alive(True)


ARGS = argparse.ArgumentParser(description="Run simple HTTP server.")
ARGS.add_argument(
    '--host', action="store", dest='host',
    default='127.0.0.1', help='Host name')
ARGS.add_argument(
    '--port', action="store", dest='port',
    default=8080, type=int, help='Port number')
# make iocp and ssl mutually exclusive because ProactorEventLoop is
# incompatible with SSL
group = ARGS.add_mutually_exclusive_group()
group.add_argument(
    '--iocp', action="store_true", dest='iocp', help='Windows IOCP event loop')
group.add_argument(
    '--ssl', action="store_true", dest='ssl', help='Run ssl mode.')
ARGS.add_argument(
    '--sslcert', action="store", dest='certfile', help='SSL cert file.')
ARGS.add_argument(
    '--sslkey', action="store", dest='keyfile', help='SSL key file.')


def main():
    args = ARGS.parse_args()

    if ':' in args.host:
        args.host, port = args.host.split(':', 1)
        args.port = int(port)

    if args.iocp:
        from asyncio import windows_events
        sys.argv.remove('--iocp')
        logging.info('using iocp')
        el = windows_events.ProactorEventLoop()
        asyncio.set_event_loop(el)

    if args.ssl:
        here = os.path.join(os.path.dirname(__file__), 'tests')

        if args.certfile:
            certfile = args.certfile or os.path.join(here, 'sample.crt')
            keyfile = args.keyfile or os.path.join(here, 'sample.key')
        else:
            certfile = os.path.join(here, 'sample.crt')
            keyfile = os.path.join(here, 'sample.key')

        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sslcontext.load_cert_chain(certfile, keyfile)
    else:
        sslcontext = None

    loop = asyncio.get_event_loop()
    f = loop.create_server(
        lambda: HttpRequestHandler(debug=True, keep_alive=75),
        args.host, args.port,
        ssl=sslcontext)
    svr = loop.run_until_complete(f)
    socks = svr.sockets
    print('serving on', socks[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
