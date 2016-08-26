import asyncio
import gc
import json
import os
import os.path
import unittest
import zlib
from unittest import mock

from multidict import MultiDict

from aiohttp import ClientSession, FormData, log, request, web
from aiohttp.protocol import HttpVersion, HttpVersion10, HttpVersion11
from aiohttp.streams import EOF_MARKER
from aiohttp.test_utils import unused_port

try:
    import ssl
except:
    ssl = False


@asyncio.coroutine
def test_simple_get(loop, test_client):

    @asyncio.coroutine
    def handler(request):
        body = yield from request.read()
        assert b'' == body
        return web.Response(body=b'OK')

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    client = yield from test_client(app)

    resp = yield from client.get('/')
    assert 200 == resp.status
    txt = yield from resp.text()
    assert 'OK' == txt


@asyncio.coroutine
def test_handler_returns_not_response(loop, test_server, test_client):
    logger = mock.Mock()

    @asyncio.coroutine
    def handler(request):
        return 'abc'

    app = web.Application(loop=loop)
    app.router.add_get('/', handler)
    server = yield from test_server(app, logger=logger)
    client = yield from test_client(server)

    resp = yield from client.get('/')
    assert 500 == resp.status

    logger.exception.assert_called_with("Error handling request")


class TestWebFunctional(unittest.TestCase):

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

    def test_head_returns_empty_body(self):

        @asyncio.coroutine
        def handler(request):
            body = yield from request.read()
            self.assertEqual(b'', body)
            return web.Response(body=b'test')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('HEAD', '/', handler)
            with ClientSession(loop=self.loop) as session:
                resp = yield from session.head(url, version=HttpVersion11)
                self.assertEqual(200, resp.status)
                txt = yield from resp.text()
                self.assertEqual('', txt)
                resp.close()

                resp = yield from session.head(url, version=HttpVersion11)
                self.assertEqual(200, resp.status)
                txt = yield from resp.text()
                self.assertEqual('', txt)
                resp.close()

        self.loop.run_until_complete(go())

    def test_post_form(self):

        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual({'a': '1', 'b': '2'}, dict(data))
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data={'a': 1, 'b': 2},
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK', txt)

        self.loop.run_until_complete(go())

    def test_post_text(self):

        @asyncio.coroutine
        def handler(request):
            data = yield from request.text()
            self.assertEqual('русский', data)
            data2 = yield from request.text()
            self.assertEqual(data, data2)
            return web.Response(text=data)

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data='русский',
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('русский', txt)

        self.loop.run_until_complete(go())

    def test_post_json(self):

        dct = {'key': 'текст'}

        @asyncio.coroutine
        def handler(request):
            data = yield from request.json()
            self.assertEqual(dct, data)
            data2 = yield from request.json(loads=json.loads)
            self.assertEqual(data, data2)
            with self.assertWarns(DeprecationWarning):
                data3 = yield from request.json(loader=json.loads)
            self.assertEqual(data, data3)
            resp = web.Response()
            resp.content_type = 'application/json'
            resp.body = json.dumps(data).encode('utf8')
            return resp

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            headers = {'Content-Type': 'application/json'}
            resp = yield from request('POST', url, data=json.dumps(dct),
                                      headers=headers,
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            data = yield from resp.json()
            self.assertEqual(dct, data)

        self.loop.run_until_complete(go())

    def test_render_redirect(self):

        @asyncio.coroutine
        def handler(request):
            raise web.HTTPMovedPermanently(location='/path')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop,
                                      allow_redirects=False)
            self.assertEqual(301, resp.status)
            txt = yield from resp.text()
            self.assertEqual('301: Moved Permanently', txt)
            self.assertEqual('/path', resp.headers['location'])

        self.loop.run_until_complete(go())

    def test_post_single_file(self):

        here = os.path.dirname(__file__)

        def check_file(fs):
            fullname = os.path.join(here, fs.filename)
            with open(fullname, 'r') as f:
                test_data = f.read().encode()
                data = fs.file.read()
                self.assertEqual(test_data, data)

        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual(['sample.crt'], list(data.keys()))
            for fs in data.values():
                check_file(fs)
                fs.file.close()
            resp = web.Response(body=b'OK')
            return resp

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            f = open(os.path.join(here, 'sample.crt'))
            resp = yield from request('POST', url, data=[f],
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            resp.close()
            f.close()

        self.loop.run_until_complete(go())

    def test_files_upload_with_same_key(self):
        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            files = data.getall('file')
            _file_names = []
            for _file in files:
                self.assertFalse(_file.file.closed)
                if _file.filename == 'test1.jpeg':
                    self.assertEqual(_file.file.read(), b'binary data 1')
                if _file.filename == 'test2.jpeg':
                    self.assertEqual(_file.file.read(), b'binary data 2')
                _file_names.append(_file.filename)
            self.assertCountEqual(_file_names, ['test1.jpeg', 'test2.jpeg'])
            resp = web.Response(body=b'OK')
            return resp

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            _data = FormData()
            _data.add_field('file', b'binary data 1',
                            content_type='image/jpeg',
                            filename='test1.jpeg')
            _data.add_field('file', b'binary data 2',
                            content_type='image/jpeg',
                            filename='test2.jpeg')
            resp = yield from request('POST', url, data=_data,
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_post_files(self):

        here = os.path.dirname(__file__)

        f1 = open(os.path.join(here, 'sample.crt'))
        f2 = open(os.path.join(here, 'sample.key'))

        def check_file(fs):
            fullname = os.path.join(here, fs.filename)
            with open(fullname, 'r') as f:
                test_data = f.read().encode()
                data = fs.file.read()
                self.assertEqual(test_data, data)

        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual(['sample.crt', 'sample.key'], list(data.keys()))
            for fs in data.values():
                check_file(fs)
                fs.file.close()
            resp = web.Response(body=b'OK')
            return resp

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data=[f1, f2],
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            resp.close()

        self.loop.run_until_complete(go())
        f1.close()
        f2.close()

    def test_release_post_data(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.release()
            chunk = yield from request.content.readany()
            self.assertIs(EOF_MARKER, chunk)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data='post text',
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_POST_DATA_with_content_transfer_encoding(self):
        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual(b'123', data['name'])
            return web.Response()

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)

            form = FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            resp = yield from request(
                'post', url, data=form,
                loop=self.loop)

            self.assertEqual(200, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_post_form_with_duplicate_keys(self):

        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            lst = list(sorted(data.items()))
            self.assertEqual([('a', '1'), ('a', '2')], lst)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request(
                'POST', url,
                data=MultiDict([('a', 1), ('a', 2)]),
                loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK', txt)

        self.loop.run_until_complete(go())

    def test_repr_for_application(self):

        @asyncio.coroutine
        def go():
            app, _, _ = yield from self.create_server('POST', '/')
            self.assertEqual("<Application>", repr(app))

        self.loop.run_until_complete(go())

    def test_expect_default_handler_unknown(self):
        """Test default Expect handler for unknown Expect value.

        A server that does not understand or is unable to comply with any of
        the expectation values in the Expect field of a request MUST respond
        with appropriate error status. The server MUST respond with a 417
        (Expectation Failed) status if any of the expectations cannot be met
        or, if there are other problems with the request, some other 4xx
        status.

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.20
        """
        @asyncio.coroutine
        def handler(request):
            yield from request.post()
            self.fail('Handler should not proceed to this point in case of '
                      'unknown Expect header')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, headers={'Expect': 'SPAM'},
                                      loop=self.loop)
            self.assertEqual(417, resp.status)
        self.loop.run_until_complete(go())

    def test_100_continue(self):
        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual(b'123', data['name'])
            return web.Response()

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)

            form = FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            resp = yield from request(
                'post', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)

            self.assertEqual(200, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_100_continue_custom(self):

        expect_received = False

        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual(b'123', data['name'])
            return web.Response()

        @asyncio.coroutine
        def expect_handler(request):
            nonlocal expect_received
            expect_received = True
            if request.version == HttpVersion11:
                request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

        @asyncio.coroutine
        def go():
            nonlocal expect_received

            app, _, url = yield from self.create_server('POST', '/')
            app.router.add_route(
                'POST', '/', handler, expect_handler=expect_handler)

            form = FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            resp = yield from request(
                'post', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)

            self.assertEqual(200, resp.status)
            self.assertTrue(expect_received)
            resp.close()

        self.loop.run_until_complete(go())

    def test_100_continue_custom_response(self):

        auth_err = False

        @asyncio.coroutine
        def handler(request):
            data = yield from request.post()
            self.assertEqual(b'123', data['name'])
            return web.Response()

        @asyncio.coroutine
        def expect_handler(request):
            if request.version == HttpVersion11:
                if auth_err:
                    return web.HTTPForbidden()

                request.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

        @asyncio.coroutine
        def go():
            nonlocal auth_err

            app, _, url = yield from self.create_server('POST', '/')
            app.router.add_route(
                'POST', '/', handler, expect_handler=expect_handler)

            form = FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            resp = yield from request(
                'post', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)

            self.assertEqual(200, resp.status)
            resp.close()

            auth_err = True
            resp = yield from request(
                'post', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)
            self.assertEqual(403, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_100_continue_for_not_found(self):

        @asyncio.coroutine
        def handler(request):
            return web.Response()

        @asyncio.coroutine
        def go():
            app, _, url = yield from self.create_server('POST', '/')
            app.router.add_route('POST', '/', handler)

            form = FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            resp = yield from request(
                'post', url + 'not_found', data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)

            self.assertEqual(404, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_100_continue_for_not_allowed(self):

        @asyncio.coroutine
        def handler(request):
            return web.Response()

        @asyncio.coroutine
        def go():
            app, _, url = yield from self.create_server('POST', '/')
            app.router.add_route('POST', '/', handler)

            form = FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            resp = yield from request(
                'GET', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)

            self.assertEqual(405, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_http11_keep_alive_default(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.read()
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop,
                                      version=HttpVersion11)
            self.assertNotIn('CONNECTION', resp.headers)
            resp.close()

        self.loop.run_until_complete(go())

    def test_http10_keep_alive_default(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.read()
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            with ClientSession(loop=self.loop) as session:
                resp = yield from session.get(url,
                                              version=HttpVersion10)
                self.assertEqual(resp.version, HttpVersion10)
                self.assertEqual('keep-alive', resp.headers['CONNECTION'])
                resp.close()

        self.loop.run_until_complete(go())

    def test_http09_keep_alive_default(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.read()
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            headers = {'Connection': 'keep-alive'}  # should be ignored
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop,
                                      headers=headers,
                                      version=HttpVersion(0, 9))
            self.assertNotIn('CONNECTION', resp.headers)
            resp.close()

        self.loop.run_until_complete(go())

    def test_http10_keep_alive_with_headers_close(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.read()
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            headers = {'Connection': 'close'}
            resp = yield from request('GET', url, loop=self.loop,
                                      headers=headers, version=HttpVersion10)
            self.assertNotIn('CONNECTION', resp.headers)
            resp.close()

        self.loop.run_until_complete(go())

    def test_http10_keep_alive_with_headers(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.read()
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            headers = {'Connection': 'keep-alive'}
            resp = yield from request('GET', url, loop=self.loop,
                                      headers=headers, version=HttpVersion10)
            self.assertEqual('keep-alive', resp.headers['CONNECTION'])
            resp.close()

        self.loop.run_until_complete(go())

    def test_upload_file(self):

        here = os.path.dirname(__file__)
        fname = os.path.join(here, 'software_development_in_picture.jpg')
        with open(fname, 'rb') as f:
            data = f.read()

        @asyncio.coroutine
        def handler(request):
            form = yield from request.post()
            raw_data = form['file'].file.read()
            self.assertEqual(data, raw_data)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url,
                                      data={'file': data},
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            resp.close()

        self.loop.run_until_complete(go())

    def test_upload_file_object(self):

        here = os.path.dirname(__file__)
        fname = os.path.join(here, 'software_development_in_picture.jpg')
        with open(fname, 'rb') as f:
            data = f.read()

        @asyncio.coroutine
        def handler(request):
            form = yield from request.post()
            raw_data = form['file'].file.read()
            self.assertEqual(data, raw_data)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            f = open(fname, 'rb')
            resp = yield from request('POST', url,
                                      data={'file': f},
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            resp.close()
            f.close()

        self.loop.run_until_complete(go())

    def test_empty_content_for_query_without_body(self):

        @asyncio.coroutine
        def handler(request):
            self.assertFalse(request.has_body)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK', txt)

        self.loop.run_until_complete(go())

    def test_empty_content_for_query_with_body(self):

        @asyncio.coroutine
        def handler(request):
            self.assertTrue(request.has_body)
            body = yield from request.read()
            return web.Response(body=body)

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data=b'data',
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('data', txt)

        self.loop.run_until_complete(go())

    def test_get_with_empty_arg(self):

        @asyncio.coroutine
        def handler(request):
            self.assertIn('arg', request.GET)
            self.assertEqual('', request.GET['arg'])
            return web.Response()

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url+'?arg', loop=self.loop)
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_large_header(self):

        @asyncio.coroutine
        def handler(request):
            return web.Response()

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            headers = {'Long-Header': 'ab' * 8129}
            resp = yield from request('GET', url,
                                      headers=headers,
                                      loop=self.loop)
            self.assertEqual(400, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_large_header_allowed(self):

        @asyncio.coroutine
        def handler(request):
            return web.Response()

        @asyncio.coroutine
        def go():
            handler_kwargs = {'max_field_size': 81920}
            _, srv, url = yield from self.create_server(
                'GET', '/', handler, handler_kwargs=handler_kwargs)
            headers = {'Long-Header': 'ab' * 8129}
            resp = yield from request('GET', url,
                                      headers=headers,
                                      loop=self.loop)
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_get_with_empty_arg_with_equal(self):

        @asyncio.coroutine
        def handler(request):
            self.assertIn('arg', request.GET)
            self.assertEqual('', request.GET['arg'])
            return web.Response()

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url+'?arg=', loop=self.loop)
            self.assertEqual(200, resp.status)
            yield from resp.release()

        self.loop.run_until_complete(go())

    def test_response_with_precompressed_body(self):
        @asyncio.coroutine
        def handler(request):
            headers = {'Content-Encoding': 'gzip'}
            deflated_data = zlib.compress(b'mydata')
            return web.Response(body=deflated_data, headers=headers)

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            client = ClientSession(loop=self.loop)
            resp = yield from client.get(url)
            self.assertEqual(200, resp.status)
            data = yield from resp.read()
            self.assertEqual(b'mydata', data)
            self.assertEqual(resp.headers.get('CONTENT-ENCODING'), 'deflate')
            yield from resp.release()
            client.close()

    def test_stream_response_multiple_chunks(self):
        @asyncio.coroutine
        def handler(request):
            resp = web.StreamResponse()
            resp.enable_chunked_encoding()
            yield from resp.prepare(request)
            resp.write(b'x')
            resp.write(b'y')
            resp.write(b'z')
            return resp

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            client = ClientSession(loop=self.loop)
            resp = yield from client.get(url)
            self.assertEqual(200, resp.status)
            data = yield from resp.read()
            self.assertEqual(b'xyz', data)
            yield from resp.release()
            client.close()

        self.loop.run_until_complete(go())

    def test_start_without_routes(self):
        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server(None, '/', None)
            client = ClientSession(loop=self.loop)
            resp = yield from client.get(url)
            self.assertEqual(404, resp.status)
            yield from resp.release()
            client.close()

        self.loop.run_until_complete(go())
