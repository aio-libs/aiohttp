import asyncio
import json
import os.path
import socket
import unittest
from aiohttp import log, web, request, FormData, ClientSession
from aiohttp.multidict import MultiDict
from aiohttp.protocol import HttpVersion, HttpVersion10, HttpVersion11
from aiohttp.streams import EOF_MARKER


class TestWebFunctional(unittest.TestCase):

    def setUp(self):
        self.handler = None
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        if self.handler:
            self.loop.run_until_complete(self.handler.finish_connections())
        self.loop.close()

    def find_unused_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @asyncio.coroutine
    def create_server(self, method, path, handler=None):
        app = web.Application(loop=self.loop)
        if handler:
            app.router.add_route(method, path, handler)

        port = self.find_unused_port()
        self.handler = app.make_handler(
            debug=True, keep_alive_on=False,
            access_log=log.access_logger)
        srv = yield from self.loop.create_server(
            self.handler, '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port) + path
        self.addCleanup(srv.close)
        return app, srv, url

    def test_simple_get(self):

        @asyncio.coroutine
        def handler(request):
            body = yield from request.read()
            self.assertEqual(b'', body)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, srv, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('OK', txt)

        self.loop.run_until_complete(go())

    def test_handler_returns_not_response(self):

        @asyncio.coroutine
        def handler(request):
            return 'abc'

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(500, resp.status)

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
            data2 = yield from request.json()
            self.assertEqual(data, data2)
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

            resp = yield from request('GET', url + '/../../', loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

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

            resp = yield from request('GET', url + 'fake', loop=self.loop)
            self.assertEqual(404, resp.status)
            resp.close()

            resp = yield from request('GET', url + '/../../', loop=self.loop)
            self.assertEqual(404, resp.status)
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
            resp.close(force=True)

            auth_err = True
            resp = yield from request(
                'post', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)
            self.assertEqual(403, resp.status)
            resp.close(force=True)

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

    def test_http10_keep_alive_default(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.read()
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('GET', '/', handler)
            resp = yield from request('GET', url, loop=self.loop,
                                      version=HttpVersion10)
            self.assertEqual('close', resp.headers['CONNECTION'])
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
            self.assertEqual('close', resp.headers['CONNECTION'])
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
            self.assertEqual('close', resp.headers['CONNECTION'])
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

    def test_stream_response_multiple_chunks(self):
        @asyncio.coroutine
        def handler(request):
            resp = web.StreamResponse()
            resp.enable_chunked_encoding()
            resp.start(request)
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

        self.loop.run_until_complete(go())
