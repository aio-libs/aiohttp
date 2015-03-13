import asyncio
import json
import os.path
import socket
import unittest
import tempfile
from aiohttp import web, request, FormData
from aiohttp.multidict import MultiDict
from aiohttp.protocol import HttpVersion11
from aiohttp.streams import EOF_MARKER


class TestWebFunctional(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
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
        srv = yield from self.loop.create_server(
            app.make_handler(keep_alive=None), '127.0.0.1', port)
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
            with open(fullname, 'rb') as f:
                test_data = f.read()
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

        self.loop.run_until_complete(go())

    def test_post_files(self):

        here = os.path.dirname(__file__)

        f1 = open(os.path.join(here, 'sample.crt'))
        f2 = open(os.path.join(here, 'sample.key'))

        def check_file(fs):
            fullname = os.path.join(here, fs.filename)
            with open(fullname, 'rb') as f:
                test_data = f.read()
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

        self.loop.run_until_complete(go())

    def test_release_post_data(self):

        @asyncio.coroutine
        def handler(request):
            yield from request.release()
            chunk = yield from request.payload.readany()
            self.assertIs(EOF_MARKER, chunk)
            return web.Response(body=b'OK')

        @asyncio.coroutine
        def go():
            _, _, url = yield from self.create_server('POST', '/', handler)
            resp = yield from request('POST', url, data='post text',
                                      loop=self.loop)
            self.assertEqual(200, resp.status)

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

        self.loop.run_until_complete(go())

    def test_static_file(self):

        @asyncio.coroutine
        def go(tmpdirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', tmpdirname)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            txt = yield from resp.text()
            self.assertEqual('file content', txt)
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('application/octet-stream', ct)

            resp = yield from request('GET', url + 'fake', loop=self.loop)
            self.assertEqual(404, resp.status)
            resp = yield from request('GET', url + '/../../', loop=self.loop)
            self.assertEqual(404, resp.status)

        with tempfile.TemporaryDirectory() as tmpdirname:
            with tempfile.NamedTemporaryFile(dir=tmpdirname) as fp:
                filename = os.path.basename(fp.name)
                fp.write(b'file content')
                fp.flush()
                fp.seek(0)
                self.loop.run_until_complete(go(tmpdirname, filename))

    def test_static_file_with_content_type(self):

        @asyncio.coroutine
        def go(dirname, filename):
            app, _, url = yield from self.create_server(
                'GET', '/static/' + filename
            )
            app.router.add_static('/static', dirname)

            resp = yield from request('GET', url, loop=self.loop)
            self.assertEqual(200, resp.status)
            body = yield from resp.read()
            with open(os.path.join(dirname, filename), 'rb') as f:
                content = f.read()
                self.assertEqual(content, body)
            ct = resp.headers['CONTENT-TYPE']
            self.assertEqual('image/jpeg', ct)

            resp = yield from request('GET', url + 'fake', loop=self.loop)
            self.assertEqual(404, resp.status)
            resp = yield from request('GET', url + '/../../', loop=self.loop)
            self.assertEqual(404, resp.status)

        here = os.path.dirname(__file__)
        filename = os.path.join(here, 'software_development_in_picture.jpg')
        self.loop.run_until_complete(go(here, filename))

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

            auth_err = True
            resp = yield from request(
                'post', url, data=form,
                expect100=True,  # wait until server returns 100 continue
                loop=self.loop)
            self.assertEqual(403, resp.status)

        self.loop.run_until_complete(go())
