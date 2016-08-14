import asyncio
import gc
import os
import unittest

import aiohttp

from aiohttp import log, request, web
from aiohttp.file_sender import FileSender
from aiohttp.test_utils import unused_port

try:
    import ssl
except:
    ssl = False


class StaticFileMixin(unittest.TestCase):

    def setUp(self):
        self.handler = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())
        self.loop.stop()
        self.loop.run_forever()
        self.loop.close()
        gc.collect()

    @asyncio.coroutine
    def create_server(self, method, path, handler=None, ssl_ctx=None,
                      logger=log.server_logger, handler_kwargs=None):
        app = web.Application(
            loop=self.loop)
        if handler:
            app.router.add_route(method, path, handler)

        port = unused_port()
        self.handler = app.make_handler(
            keep_alive_on=False,
            access_log=log.access_logger,
            logger=logger,
            **(handler_kwargs or {}))
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port, ssl=ssl_ctx)
        protocol = "https" if ssl_ctx else "http"
        url = "{}://127.0.0.1:{}".format(protocol, port) + path
        self.addCleanup(srv.close)
        return app, srv, url

        app.router.add_static = self.patch_sendfile(app.router.add_static)

        return app, srv, url

    def test_static_file(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('file content', txt.rstrip())
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('application/octet-stream', ct)
            self.assertEqual(resp.headers.get('CONTENT-ENCODING'), None)
            resp.close()

            resp = yield from request('GET', url + 'fake', loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

            resp = yield from request('GET', url + 'x' * 500, loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

            resp = yield from request('GET', url + '/../../', loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'data.unknown_mime_type'
        self.loop.run_until_complete(go(here, filename))

    @unittest.skipUnless(ssl, "ssl not supported")
    def test_static_file_ssl(self):

        @asyncio.coroutine
        def go(dirname, filename):
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_ctx.load_cert_chain(
                os.path.join(dirname, 'sample.crt'),
                os.path.join(dirname, 'sample.key')
            )
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename, ssl_ctx=ssl_ctx
            )
            app.router.add_static('/static', dirname)

            conn = aiohttp.TCPConnector(verify_ssl=False, loop=self.loop)
            session = aiohttp.ClientSession(connector=conn)

            resp = yield from session.request('GET', url)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('file content', txt.rstrip())
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('application/octet-stream', ct)
            self.assertEqual(resp.headers.get('CONTENT-ENCODING'), None)
            resp.close()
            session.close()

        here = os.path.dirname(__file__)
        filename = 'data.unknown_mime_type'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_with_content_type(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname, chunk_size=16)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            body = yield from resp.read()
            with open(os.path.join(dirname, filename), 'rb') as f:
                content = f.read()
                self.assertEqual(content, body)
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('image/jpeg', ct)
            self.assertEqual(resp.headers.get('CONTENT-ENCODING'), None)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'software_development_in_picture.jpg'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_with_content_encoding(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            body = yield from resp.read()
            self.assertEqual(b'hello aiohttp\n', body)
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('text/plain', ct)
            encoding = resp.headers['CONTENT-ENCODING']
            self.assertEqual('gzip', encoding)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'hello.txt.gz'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_directory_traversal_attack(self):

        @asyncio.coroutine
        def go(dirname, relpath):
            self.assertTrue(os.path.isfile(os.path.join(dirname, relpath)))

            app, _, url = yield from self.create_server('GET', '/static/')
            app.router.add_static('/static', dirname)

            url_relpath = url + relpath
            resp = yield from request('GET', url_relpath, loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

            url_relpath2 = url + 'dir/../' + filename
            resp = yield from request('GET', url_relpath2, loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

            url_abspath = \
                url + os.path.abspath(os.path.join(dirname, filename))
            resp = yield from request('GET', url_abspath, loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

        here = os.path.dirname(__file__)
        filename = '../README.rst'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_if_modified_since(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            lastmod = resp.headers.get('Last-Modified')
            self.assertIsNotNone(lastmod)
            resp.close()

            resp = yield from request('GET', url, loop=self.loop,
                                      headers={'If-Modified-Since': lastmod})
            self.assertEqual(304, resp.status)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'data.unknown_mime_type'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_if_modified_since_past_date(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'
            resp = yield from request('GET', url, loop=self.loop,
                                      headers={'If-Modified-Since': lastmod})
            self.assertEqual(200, resp.status)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'data.unknown_mime_type'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_if_modified_since_future_date(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'
            resp = yield from request('GET', url, loop=self.loop,
                                      headers={'If-Modified-Since': lastmod})
            self.assertEqual(304, resp.status)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'data.unknown_mime_type'
        self.loop.run_until_complete(go(here, filename))

    def test_static_file_if_modified_since_invalid_date(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            lastmod = 'not a valid HTTP-date'
            resp = yield from request('GET', url, loop=self.loop,
                                      headers={'If-Modified-Since': lastmod})
            self.assertEqual(200, resp.status)
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'data.unknown_mime_type'
        self.loop.run_until_complete(go(here, filename))

    def test_static_route_path_existence_check(self):
        directory = os.path.dirname(__file__)
        web.StaticRoute(None, "/", directory)

        nodirectory = os.path.join(directory, "nonexistent-uPNiOEAg5d")
        with self.assertRaises(ValueError):
            web.StaticRoute(None, "/", nodirectory)

    def test_static_file_huge(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('application/octet-stream', ct)
            self.assertIsNone(resp.headers.get('CONTENT-ENCODING'))
            self.assertEqual(int(resp.headers.get('CONTENT-LENGTH')),
                             file_st.st_size)

            f = open(fname, 'rb')
            off = 0
            cnt = 0
            while off < file_st.st_size:
                chunk = yield from resp.content.readany()
                expected = f.read(len(chunk))
                self.assertEqual(chunk, expected)
                off += len(chunk)
                cnt += 1
            f.close()
            resp.close()

        here = os.path.dirname(__file__)
        filename = 'huge_data.unknown_mime_type'

        # fill 100MB file
        fname = os.path.join(here, filename)
        with open(fname, 'w') as f:
            for i in range(1024*20):
                f.write(chr(i % 64 + 0x20) * 1024)
        self.addCleanup(os.unlink, fname)
        file_st = os.stat(fname)

        self.loop.run_until_complete(go(here, filename))


class TestStaticFileSendfileFallback(StaticFileMixin,
                                     unittest.TestCase):
    def patch_sendfile(self, add_static):
        def f(*args, **kwargs):
            route = add_static(*args, **kwargs)
            file_sender = FileSender()
            file_sender._sendfile = file_sender._sendfile_fallback
            return route
        return f
