import asyncio
import gc
import os
import pathlib
import unittest

import pytest

import aiohttp
from aiohttp import log, request, web
from aiohttp.file_sender import FileSender
from aiohttp.test_utils import loop_context, unused_port

try:
    import ssl
except:
    ssl = False


try:
    import uvloop
except:
    uvloop = None


LOOP_FACTORIES = [asyncio.new_event_loop]
if uvloop:
    LOOP_FACTORIES.append(uvloop.new_event_loop)


@pytest.yield_fixture(params=LOOP_FACTORIES)
def loop(request):
    with loop_context(request.param) as loop:
        yield loop


@pytest.fixture(params=['sendfile', 'fallback'], ids=['sendfile', 'fallback'])
def sender(request):
    def maker(*args, **kwargs):
        ret = FileSender(*args, **kwargs)
        if request.param == 'fallback':
            ret._sendfile = ret._sendfile_fallback
        return ret
    return maker


@asyncio.coroutine
def test_static_file_ok(loop, test_client, sender):
    filepath = pathlib.Path(__file__).parent / 'data.unknown_mime_type'

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert resp.status == 200
    txt = yield from resp.text()
    assert 'file content' == txt.rstrip()
    assert 'application/octet-stream' == resp.headers['Content-Type']
    assert resp.headers.get('Content-Encoding') is None
    yield from resp.release()


@asyncio.coroutine
def test_static_file_not_exists(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/fake')
    assert resp.status == 404
    yield from resp.release()


@asyncio.coroutine
def test_static_file_name_too_long(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/x*500')
    assert resp.status == 404
    yield from resp.release()


@asyncio.coroutine
def test_static_file_upper_directory(loop, test_client):

    app = web.Application(loop=loop)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/../../')
    assert resp.status == 404
    yield from resp.release()


@asyncio.coroutine
def test_static_file_with_content_type(loop, test_client, sender):
    filepath = (pathlib.Path(__file__).parent /
                'software_development_in_picture.jpg')

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender(chunk_size=16).send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert resp.status == 200
    body = yield from resp.read()
    with filepath.open('rb') as f:
        content = f.read()
        assert content == body
    assert resp.headers['Content-Type'] == 'image/jpeg'
    assert resp.headers.get('Content-Encoding') is None
    resp.close()


@asyncio.coroutine
def test_static_file_with_content_encoding(loop, test_client, sender):
    filepath = pathlib.Path(__file__).parent / 'hello.txt.gz'

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    body = yield from resp.read()
    assert b'hello aiohttp\n' == body
    ct = resp.headers['CONTENT-TYPE']
    assert 'text/plain' == ct
    encoding = resp.headers['CONTENT-ENCODING']
    assert 'gzip' == encoding
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    lastmod = resp.headers.get('Last-Modified')
    assert lastmod is not None
    resp.close()

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 304 == resp.status
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since_past_date(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    lastmod = 'Mon, 1 Jan 1990 01:01:01 GMT'

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since_invalid_date(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    lastmod = 'not a valid HTTP-date'

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 200 == resp.status
    resp.close()


@asyncio.coroutine
def test_static_file_if_modified_since_future_date(loop, test_client, sender):
    filename = 'data.unknown_mime_type'
    filepath = pathlib.Path(__file__).parent / filename

    @asyncio.coroutine
    def handler(request):
        resp = yield from sender().send(request, filepath)
        return resp

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(lambda loop: app)

    lastmod = 'Fri, 31 Dec 9999 23:59:59 GMT'

    resp = yield from client.get('/', headers={'If-Modified-Since': lastmod})
    assert 304 == resp.status
    resp.close()


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
