"""HTTP client functional tests."""

import binascii
import gc
import io
import os.path
import json
import http.cookies
import asyncio
import socket
import unittest
from unittest import mock

from multidict import MultiDict

import aiohttp
from aiohttp import client, helpers
from aiohttp import test_utils
from aiohttp.multipart import MultipartWriter


def find_unused_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestHttpClientFunctional(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        # just in case if we have transport close callbacks
        test_utils.run_briefly(self.loop)

        self.loop.close()
        gc.collect()

    def test_HTTP_200_OK_METHOD(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            for meth in ('get', 'post', 'put', 'delete', 'head'):
                r = self.loop.run_until_complete(
                    client.request(meth, httpd.url('method', meth),
                                   loop=self.loop))
                content1 = self.loop.run_until_complete(r.read())
                content2 = self.loop.run_until_complete(r.read())
                content = content1.decode()

                self.assertEqual(r.status, 200)
                if meth == 'head':
                    self.assertEqual(b'', content1)
                else:
                    self.assertIn('"method": "%s"' % meth.upper(), content)
                self.assertEqual(content1, content2)
                r.close()

    def test_HTTP_200_OK_METHOD_connector(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            conn = aiohttp.TCPConnector(
                conn_timeout=0.2, resolve=True, loop=self.loop)
            conn.clear_resolved_hosts()

            for meth in ('get', 'post', 'put', 'delete', 'head'):
                r = self.loop.run_until_complete(
                    client.request(
                        meth, httpd.url('method', meth),
                        connector=conn, loop=self.loop))
                content1 = self.loop.run_until_complete(r.read())
                content2 = self.loop.run_until_complete(r.read())
                content = content1.decode()

                self.assertEqual(r.status, 200)
                if meth == 'head':
                    self.assertEqual(b'', content1)
                else:
                    self.assertIn('"method": "%s"' % meth.upper(), content)
                self.assertEqual(content1, content2)
                r.close()

    def test_use_global_loop(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            try:
                asyncio.set_event_loop(self.loop)
                r = self.loop.run_until_complete(
                    client.request('get', httpd.url('method', 'get')))
            finally:
                asyncio.set_event_loop(None)
            content1 = self.loop.run_until_complete(r.read())
            content2 = self.loop.run_until_complete(r.read())
            content = content1.decode()

            self.assertEqual(r.status, 200)
            self.assertIn('"method": "GET"', content)
            self.assertEqual(content1, content2)
            r.close()

    def test_HTTP_302_REDIRECT_GET(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            @asyncio.coroutine
            def go():
                r = yield from client.request('get',
                                              httpd.url('redirect', 2),
                                              loop=self.loop)

                self.assertEqual(r.status, 200)
                self.assertEqual(2, httpd['redirects'])
                r.close()
            self.loop.run_until_complete(go())

    def test_HTTP_302_REDIRECT_NON_HTTP(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            @asyncio.coroutine
            def go():
                with self.assertRaises(ValueError):
                    yield from client.request('get',
                                              httpd.url('redirect_err'),
                                              loop=self.loop)

            self.loop.run_until_complete(go())

    def test_HTTP_302_REDIRECT_POST(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('post', httpd.url('redirect', 2),
                               data={'some': 'data'}, loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()

            self.assertEqual(r.status, 200)
            self.assertIn('"method": "GET"', content)
            self.assertEqual(2, httpd['redirects'])
            r.close()

    def test_HTTP_302_REDIRECT_POST_with_content_length_header(self):
        data = json.dumps({'some': 'data'})
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('post', httpd.url('redirect', 2),
                               data=data,
                               headers={'Content-Length': str(len(data))},
                               loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()

            self.assertEqual(r.status, 200)
            self.assertIn('"method": "GET"', content)
            self.assertEqual(2, httpd['redirects'])
            r.close()

    def test_HTTP_307_REDIRECT_POST(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('post', httpd.url('redirect_307', 2),
                               data={'some': 'data'}, loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()

            self.assertEqual(r.status, 200)
            self.assertIn('"method": "POST"', content)
            self.assertEqual(2, httpd['redirects'])
            r.close()

    def test_HTTP_302_max_redirects(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('redirect', 5),
                               max_redirects=2, loop=self.loop))

            self.assertEqual(r.status, 302)
            self.assertEqual(2, httpd['redirects'])
            r.close()

    def test_HTTP_200_GET_WITH_PARAMS(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('method', 'get'),
                               params={'q': 'test'}, loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()

            self.assertIn('"query": "q=test"', content)
            self.assertEqual(r.status, 200)
            r.close()

    def test_HTTP_200_GET_MultiDict_PARAMS(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('method', 'get'),
                               params=MultiDict(
                                   [('q', 'test1'), ('q', 'test2')]),
                               loop=self.loop))
            content = self.loop.run_until_complete(r.content.read())
            content = content.decode()

            self.assertIn('"query": "q=test1&q=test2"', content)
            self.assertEqual(r.status, 200)
            r.close()

    def test_HTTP_200_GET_WITH_MIXED_PARAMS(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            @asyncio.coroutine
            def go():
                r = yield from client.request(
                    'get', httpd.url('method', 'get') + '?test=true',
                    params={'q': 'test'}, loop=self.loop)
                content = yield from r.content.read()
                content = content.decode()

                self.assertIn('"query": "test=true&q=test"', content)
                self.assertEqual(r.status, 200)
                r.close()
                # let loop to make one iteration to call connection_lost
                # and close socket
                yield from asyncio.sleep(0, loop=self.loop)
            self.loop.run_until_complete(go())

    def test_POST_DATA(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')
            r = self.loop.run_until_complete(
                client.request('post', url, data={'some': 'data'},
                               loop=self.loop))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.json())
            self.assertEqual({'some': ['data']}, content['form'])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_DATA_with_explicit_formdata(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')
            form = aiohttp.FormData()
            form.add_field('name', 'text')
            r = self.loop.run_until_complete(
                client.request('post', url,
                               data=form,
                               loop=self.loop))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.json())
            self.assertEqual({'name': ['text']}, content['form'])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_DATA_with_charset(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            form = aiohttp.FormData()
            form.add_field('name', 'текст',
                           content_type='text/plain; charset=koi8-r')

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=form,
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())

            self.assertEqual(1, len(content['multipart-data']))
            field = content['multipart-data'][0]
            self.assertEqual('name', field['name'])
            self.assertEqual('текст', field['data'])
            self.assertEqual(r.status, 200)

    def test_POST_DATA_with_content_transfer_encoding(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            form = aiohttp.FormData()
            form.add_field('name', b'123',
                           content_transfer_encoding='base64')

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=form,
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())

            self.assertEqual(1, len(content['multipart-data']))
            field = content['multipart-data'][0]
            self.assertEqual('name', field['name'])
            self.assertEqual(b'123', binascii.a2b_base64(field['data']))
            # self.assertEqual('base64', field['content-transfer-encoding'])
            self.assertEqual(r.status, 200)

    def test_POST_MultiDict(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')
            r = self.loop.run_until_complete(
                client.request('post', url, data=MultiDict(
                    [('q', 'test1'), ('q', 'test2')]),
                    loop=self.loop))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.json())
            self.assertEqual({'q': ['test1', 'test2']}, content['form'])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_DATA_DEFLATE(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')
            r = self.loop.run_until_complete(
                client.request('post', url,
                               data={'some': 'data'}, compress=True,
                               loop=self.loop))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.json())
            self.assertEqual('deflate', content['compression'])
            self.assertEqual({'some': ['data']}, content['form'])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_FILES(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                r = self.loop.run_until_complete(
                    client.request(
                        'post', url, data={'some': f, 'test': b'data'},
                        chunked=1024,
                        headers={'Transfer-Encoding': 'chunked'},
                        loop=self.loop))
                content = self.loop.run_until_complete(r.json())
                files = list(
                    sorted(content['multipart-data'],
                           key=lambda d: d['name']))

                f.seek(0)
                filename = os.path.split(f.name)[-1]

                self.assertEqual(2, len(content['multipart-data']))
                self.assertEqual('some', files[0]['name'])
                self.assertEqual(filename, files[0]['filename'])
                self.assertEqual(f.read(), files[0]['data'])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_DEFLATE(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                r = self.loop.run_until_complete(
                    client.request('post', url, data={'some': f},
                                   chunked=1024, compress='deflate',
                                   loop=self.loop))

                content = self.loop.run_until_complete(r.json())

                f.seek(0)
                filename = os.path.split(f.name)[-1]

                self.assertEqual('deflate', content['compression'])
                self.assertEqual(1, len(content['multipart-data']))
                self.assertEqual(
                    'some', content['multipart-data'][0]['name'])
                self.assertEqual(
                    filename, content['multipart-data'][0]['filename'])
                self.assertEqual(
                    f.read(), content['multipart-data'][0]['data'])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_STR(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                r = self.loop.run_until_complete(
                    client.request('post', url, data=[('some', f.read())],
                                   loop=self.loop))

                content = self.loop.run_until_complete(r.json())

                f.seek(0)
                self.assertEqual(1, len(content['form']))
                self.assertIn('some', content['form'])
                self.assertEqual(f.read(), content['form']['some'][0])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_STR_SIMPLE(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                r = self.loop.run_until_complete(
                    client.request('post', url, data=f.read(), loop=self.loop))

                content = self.loop.run_until_complete(r.json())

                f.seek(0)
                self.assertEqual(f.read(), content['content'])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_LIST(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                r = self.loop.run_until_complete(
                    client.request('post', url, data=[('some', f)],
                                   loop=self.loop))

                content = self.loop.run_until_complete(r.json())

                f.seek(0)
                filename = os.path.split(f.name)[-1]

                self.assertEqual(1, len(content['multipart-data']))
                self.assertEqual(
                    'some', content['multipart-data'][0]['name'])
                self.assertEqual(
                    filename, content['multipart-data'][0]['filename'])
                self.assertEqual(
                    f.read(), content['multipart-data'][0]['data'])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_LIST_CT(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                form = aiohttp.FormData()
                form.add_field('some', f, content_type='text/plain')
                r = self.loop.run_until_complete(
                    client.request('post', url, loop=self.loop,
                                   data=form))

                content = self.loop.run_until_complete(r.json())

                f.seek(0)
                filename = os.path.split(f.name)[-1]

                self.assertEqual(1, len(content['multipart-data']))
                self.assertEqual(
                    'some', content['multipart-data'][0]['name'])
                self.assertEqual(
                    filename, content['multipart-data'][0]['filename'])
                self.assertEqual(
                    f.read(), content['multipart-data'][0]['data'])
                self.assertEqual(
                    'text/plain', content['multipart-data'][0]['content-type'])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_SINGLE(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                with self.assertRaises(ValueError):
                    self.loop.run_until_complete(
                        client.request('post', url, data=f, loop=self.loop))

    def test_POST_FILES_SINGLE_BINARY(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                r = self.loop.run_until_complete(
                    client.request('post', url, data=f, loop=self.loop))

                content = self.loop.run_until_complete(r.json())

                f.seek(0)
                self.assertEqual(0, len(content['multipart-data']))
                self.assertEqual(content['content'], f.read().decode())

                # if system cannot determine 'application/pgp-keys' MIME type
                # then use 'application/octet-stream' default
                self.assertIn(content['headers']['Content-Type'],
                              ('application/pgp-keys',
                               'application/octet-stream'))
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_FILES_IO(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            data = io.BytesIO(b'data')

            r = self.loop.run_until_complete(
                client.request('post', url, data=[data], loop=self.loop))

            content = self.loop.run_until_complete(r.json())

            self.assertEqual(1, len(content['multipart-data']))
            self.assertEqual(
                {'content-type': 'application/octet-stream',
                 'data': 'data',
                 'filename': 'unknown',
                 'filename*': "utf-8''unknown",
                 'name': 'unknown'}, content['multipart-data'][0])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_MULTIPART(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            with MultipartWriter('form-data') as writer:
                writer.append('foo')
                writer.append_json({'bar': 'баз'})
                writer.append_form([('тест', '4'), ('сетс', '2')])

            r = self.loop.run_until_complete(
                client.request('post', url, data=writer, loop=self.loop))

            content = self.loop.run_until_complete(r.json())

            self.assertEqual(3, len(content['multipart-data']))
            self.assertEqual({'content-type': 'text/plain', 'data': 'foo'},
                             content['multipart-data'][0])
            self.assertEqual({'content-type': 'application/json',
                              'data': '{"bar": "\\u0431\\u0430\\u0437"}'},
                             content['multipart-data'][1])
            self.assertEqual(
                {'content-type': 'application/x-www-form-urlencoded',
                 'data': '%D1%82%D0%B5%D1%81%D1%82=4&'
                         '%D1%81%D0%B5%D1%82%D1%81=2'},
                content['multipart-data'][2])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_FILES_IO_WITH_PARAMS(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            data = io.BytesIO(b'data')

            r = self.loop.run_until_complete(
                client.request('post', url,
                               data=(('test', 'true'),
                                     MultiDict(
                                         [('q', 't1'), ('q', 't2')]),
                                     data),
                               loop=self.loop))

            content = self.loop.run_until_complete(r.json())

            self.assertEqual(4, len(content['multipart-data']))
            self.assertEqual(
                {'content-type': 'text/plain',
                 'data': 'true',
                 'name': 'test'}, content['multipart-data'][0])
            self.assertEqual(
                {'content-type': 'application/octet-stream',
                 'data': 'data',
                 'filename': 'unknown',
                 'filename*': "utf-8''unknown",
                 'name': 'unknown'}, content['multipart-data'][1])
            self.assertEqual(
                {'content-type': 'text/plain',
                 'data': 't1',
                 'name': 'q'}, content['multipart-data'][2])
            self.assertEqual(
                {'content-type': 'text/plain',
                 'data': 't2',
                 'name': 'q'}, content['multipart-data'][3])
            self.assertEqual(r.status, 200)
            r.close()

    def test_POST_FILES_WITH_DATA(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname) as f:
                r = self.loop.run_until_complete(
                    client.request('post', url, loop=self.loop,
                                   data={'test': 'true', 'some': f}))

                content = self.loop.run_until_complete(r.json())
                files = list(
                    sorted(content['multipart-data'],
                           key=lambda d: d['name']))

                self.assertEqual(2, len(content['multipart-data']))
                self.assertEqual('test', files[1]['name'])
                self.assertEqual('true', files[1]['data'])

                f.seek(0)
                filename = os.path.split(f.name)[-1]
                self.assertEqual('some', files[0]['name'])
                self.assertEqual(filename, files[0]['filename'])
                self.assertEqual(f.read(), files[0]['data'])
                self.assertEqual(r.status, 200)
                r.close()

    def test_POST_STREAM_DATA(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            fut = helpers.create_future(self.loop)

            @asyncio.coroutine
            def stream():
                yield from fut
                yield data

            self.loop.call_later(0.01, fut.set_result, True)

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=stream(),
                    headers={'Content-Length': str(len(data))},
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())
            r.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])
            self.assertEqual('application/octet-stream',
                             content['headers']['Content-Type'])

    def test_POST_StreamReader(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            stream = aiohttp.StreamReader(loop=self.loop)
            stream.feed_data(data)
            stream.feed_eof()

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=stream,
                    headers={'Content-Length': str(len(data))},
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())
            r.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_POST_DataQueue(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            stream = aiohttp.DataQueue(loop=self.loop)
            stream.feed_data(data[:100], 100)
            stream.feed_data(data[100:], len(data[100:]))
            stream.feed_eof()

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=stream,
                    headers={'Content-Length': str(len(data))},
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())
            r.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_POST_ChunksQueue(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            here = os.path.dirname(__file__)
            fname = os.path.join(here, 'sample.key')

            with open(fname, 'rb') as f:
                data = f.read()

            stream = aiohttp.ChunksQueue(loop=self.loop)
            stream.feed_data(data[:100], 100)

            d = data[100:]
            stream.feed_data(d, len(d))
            stream.feed_eof()

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=stream,
                    headers={'Content-Length': str(len(data))},
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())
            r.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_expect_continue(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')
            r = self.loop.run_until_complete(
                client.request('post', url, data={'some': 'data'},
                               expect100=True, loop=self.loop))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.json())
            self.assertEqual('100-continue', content['headers']['Expect'])
            self.assertEqual(r.status, 200)
            r.close()

    def test_encoding(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('encoding', 'deflate'),
                               loop=self.loop))
            self.assertEqual(r.status, 200)
            r.close()

    def test_encoding2(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('encoding', 'gzip'),
                               loop=self.loop))
            self.assertEqual(r.status, 200)
            r.close()

    def test_cookies(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            c = http.cookies.Morsel()
            c.set('test3', '456', '456')

            r = self.loop.run_until_complete(
                client.request(
                    'get', httpd.url('method', 'get'), loop=self.loop,
                    cookies={'test1': '123', 'test2': c}))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.content.read())
            self.assertIn(b'"Cookie": "test1=123; test3=456"', bytes(content))
            r.close()

    def test_morsel_with_attributes(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            c = http.cookies.Morsel()
            c.set('test3', '456', '456')
            c['httponly'] = True
            c['secure'] = True
            c['max-age'] = 1000

            r = self.loop.run_until_complete(
                client.request(
                    'get', httpd.url('method', 'get'), loop=self.loop,
                    cookies={'test2': c}))
            self.assertEqual(r.status, 200)

            content = self.loop.run_until_complete(r.content.read())
            # No cookie attribute should pass here
            # they are only used as filters
            # whether to send particular cookie or not.
            # E.g. if cookie expires it just becomes thrown away.
            # Server who sent the cookie with some attributes
            # already knows them, no need to send this back again and again
            self.assertIn(b'"Cookie": "test3=456"', bytes(content))
            r.close()

    @mock.patch('aiohttp.client_reqrep.client_logger')
    def test_set_cookies(self, m_log):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            resp = self.loop.run_until_complete(
                client.request('get', httpd.url('cookies'), loop=self.loop))
            self.assertEqual(resp.status, 200)

            self.assertEqual(list(sorted(resp.cookies.keys())), ['c1', 'c2'])
            self.assertEqual(resp.cookies['c1'].value, 'cookie1')
            self.assertEqual(resp.cookies['c2'].value, 'cookie2')
            resp.close()

        m_log.warning.assert_called_with('Can not load response cookies: %s',
                                         mock.ANY)

    def test_chunked(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('chunked'), loop=self.loop))
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers.getone('TRANSFER-ENCODING'), 'chunked')
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(content['path'], '/chunked')
            r.close()

    def test_broken_connection(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request('get', httpd.url('broken'), loop=self.loop))
            self.assertEqual(r.status, 200)
            self.assertRaises(
                aiohttp.ServerDisconnectedError,
                self.loop.run_until_complete, r.json())
            r.close()

    def test_request_conn_error(self):
        with self.assertRaises(aiohttp.ClientConnectionError):
            self.loop.run_until_complete(
                client.request('get', 'http://0.0.0.0:1', loop=self.loop))

    def test_request_conn_closed(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            httpd['close'] = True
            with self.assertRaises(aiohttp.ClientHttpProcessingError):
                self.loop.run_until_complete(
                    client.request('get', httpd.url('method', 'get'),
                                   loop=self.loop))

    def test_session_close(self):
        conn = aiohttp.TCPConnector(loop=self.loop)

        with test_utils.run_server(self.loop, router=Functional) as httpd:
            r = self.loop.run_until_complete(
                client.request(
                    'get', httpd.url('keepalive') + '?close=1',
                    connector=conn, loop=self.loop))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(content['content'], 'requests=1')
            r.close()

            r = self.loop.run_until_complete(
                client.request('get', httpd.url('keepalive'),
                               connector=conn, loop=self.loop))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(content['content'], 'requests=1')
            r.close()

        conn.close()

    def test_multidict_headers(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('method', 'post')

            data = b'sample data'

            r = self.loop.run_until_complete(
                client.request(
                    'post', url, data=data,
                    headers=MultiDict(
                        {'Content-Length': str(len(data))}),
                    loop=self.loop))
            content = self.loop.run_until_complete(r.json())
            r.close()

            self.assertEqual(str(len(data)),
                             content['headers']['Content-Length'])

    def test_close_implicit_connector(self):

        @asyncio.coroutine
        def go(url):
            r = yield from client.request('GET', url, loop=self.loop)

            connection = r.connection
            self.assertIsNotNone(connection)
            connector = connection._connector
            self.assertIsNotNone(connector)
            yield from r.read()
            self.assertEqual(0, len(connector._conns))

        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('keepalive')
            self.loop.run_until_complete(go(url))

    def test_dont_close_explicit_connector(self):

        @asyncio.coroutine
        def go(url):
            connector = aiohttp.TCPConnector(loop=self.loop)

            r = yield from client.request('GET', url,
                                          connector=connector,
                                          loop=self.loop)
            yield from r.read()
            self.assertEqual(1, len(connector._conns))
            connector.close()

        with test_utils.run_server(self.loop, router=Functional) as httpd:
            url = httpd.url('keepalive')
            self.loop.run_until_complete(go(url))

    def test_server_close_keepalive_connection(self):

        class Proto(asyncio.Protocol):

            def connection_made(self, transport):
                self.transp = transport
                self.data = b''

            def data_received(self, data):
                self.data += data
                if data.endswith(b'\r\n\r\n'):
                    self.transp.write(
                        b'HTTP/1.1 200 OK\r\n'
                        b'CONTENT-LENGTH: 2\r\n'
                        b'CONNECTION: close\r\n'
                        b'\r\n'
                        b'ok')
                    self.transp.close()

            def connection_lost(self, exc):
                self.transp = None

        @asyncio.coroutine
        def go():
            server = yield from self.loop.create_server(
                Proto, '127.0.0.1', find_unused_port())

            addr = server.sockets[0].getsockname()

            connector = aiohttp.TCPConnector(loop=self.loop)

            url = 'http://{}:{}/'.format(*addr)
            for i in range(2):
                r = yield from client.request('GET', url,
                                              connector=connector,
                                              loop=self.loop)
                yield from r.read()
                self.assertEqual(0, len(connector._conns))
            connector.close()
            server.close()
            yield from server.wait_closed()

        self.loop.run_until_complete(go())

    def test_handle_keepalive_on_closed_connection(self):

        class Proto(asyncio.Protocol):

            def connection_made(self, transport):
                self.transp = transport
                self.data = b''

            def data_received(self, data):
                self.data += data
                if data.endswith(b'\r\n\r\n'):
                    self.transp.write(
                        b'HTTP/1.1 200 OK\r\n'
                        b'CONTENT-LENGTH: 2\r\n'
                        b'\r\n'
                        b'ok')
                    self.transp.close()

            def connection_lost(self, exc):
                self.transp = None

        @asyncio.coroutine
        def go():
            server = yield from self.loop.create_server(
                Proto, '127.0.0.1', find_unused_port())

            addr = server.sockets[0].getsockname()

            connector = aiohttp.TCPConnector(loop=self.loop)

            url = 'http://{}:{}/'.format(*addr)

            r = yield from client.request('GET', url,
                                          connector=connector,
                                          loop=self.loop)
            yield from r.read()
            self.assertEqual(1, len(connector._conns))

            with self.assertRaises(aiohttp.ClientError):
                yield from client.request('GET', url,
                                          connector=connector,
                                          loop=self.loop)
            self.assertEqual(0, len(connector._conns))

            connector.close()
            server.close()
            yield from server.wait_closed()

        self.loop.run_until_complete(go())

    @mock.patch('aiohttp.client_reqrep.client_logger')
    def test_session_cookies(self, m_log):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(loop=self.loop)

            resp = self.loop.run_until_complete(
                session.request('get', httpd.url('cookies')))
            self.assertEqual(resp.cookies['c1'].value, 'cookie1')
            self.assertEqual(resp.cookies['c2'].value, 'cookie2')
            resp.close()

            # Add the received cookies as shared for sending them to the test
            # server, which is only accessible via IP
            session.cookies.update(resp.cookies)

            # Assert, that we send those cookies in next requests
            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertEqual(
                content['headers']['Cookie'], 'c1=cookie1; c2=cookie2')
            r.close()
            session.close()

    def test_session_headers(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, headers={
                    "X-Real-IP": "192.168.0.1"
                })

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "X-Real-Ip", content['headers'])
            self.assertEqual(
                content['headers']["X-Real-Ip"], "192.168.0.1")
            r.close()
            session.close()

    def test_session_headers_merge(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, headers=[
                    ("X-Real-IP", "192.168.0.1"),
                    ("X-Sent-By", "requests")])

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get'),
                                headers={"X-Sent-By": "aiohttp"}))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "X-Real-Ip", content['headers'])
            self.assertIn(
                "X-Sent-By", content['headers'])
            self.assertEqual(
                content['headers']["X-Real-Ip"], "192.168.0.1")
            self.assertEqual(
                content['headers']["X-Sent-By"], "aiohttp")
            r.close()
            session.close()

    def test_session_auth(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, auth=helpers.BasicAuth("login", "pass"))

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get')))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "Authorization", content['headers'])
            self.assertEqual(
                content['headers']["Authorization"], "Basic bG9naW46cGFzcw==")
            r.close()
            session.close()

    def test_session_auth_override(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, auth=helpers.BasicAuth("login", "pass"))

            r = self.loop.run_until_complete(
                session.request('get', httpd.url('method', 'get'),
                                auth=helpers.BasicAuth("other_login", "pass")))
            self.assertEqual(r.status, 200)
            content = self.loop.run_until_complete(r.json())
            self.assertIn(
                "Authorization", content['headers'])
            self.assertEqual(
                content['headers']["Authorization"],
                "Basic b3RoZXJfbG9naW46cGFzcw==")
            r.close()
            session.close()

    def test_session_auth_header_conflict(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            session = client.ClientSession(
                loop=self.loop, auth=helpers.BasicAuth("login", "pass"))

            headers = {'Authorization': "Basic b3RoZXJfbG9naW46cGFzcw=="}
            with self.assertRaises(ValueError):
                self.loop.run_until_complete(
                    session.request('get', httpd.url('method', 'get'),
                                    headers=headers))
            session.close()

    def test_shortcuts(self):
        with test_utils.run_server(self.loop, router=Functional) as httpd:
            for meth in ('get', 'post', 'put', 'delete',
                         'head', 'patch', 'options'):
                coro = getattr(client, meth)
                r = self.loop.run_until_complete(
                    coro(httpd.url('method', meth), loop=self.loop))
                content1 = self.loop.run_until_complete(r.read())
                content2 = self.loop.run_until_complete(r.read())
                content = content1.decode()

                self.assertEqual(r.status, 200)
                if meth == 'head':
                    self.assertEqual(b'', content1)
                else:
                    self.assertIn('"method": "%s"' % meth.upper(), content)
                self.assertEqual(content1, content2)
                r.close()


class Functional(test_utils.Router):

    @test_utils.Router.define('/method/([A-Za-z]+)$')
    def method(self, match):
        self._response(self._start_response(200))

    @test_utils.Router.define('/redirect_err$')
    def redirect_err(self, match):
        self._response(
            self._start_response(302),
            headers={'Location': 'ftp://127.0.0.1/test/'})

    @test_utils.Router.define('/redirect/([0-9]+)$')
    def redirect(self, match):
        no = int(match.group(1).upper())
        rno = self._props['redirects'] = self._props.get('redirects', 0) + 1

        if rno >= no:
            self._response(
                self._start_response(302),
                headers={'Location': '/method/%s' % self._method.lower()})
        else:
            self._response(
                self._start_response(302),
                headers={'Location': self._path})

    @test_utils.Router.define('/redirect_307/([0-9]+)$')
    def redirect_307(self, match):
        no = int(match.group(1).upper())
        rno = self._props['redirects'] = self._props.get('redirects', 0) + 1

        if rno >= no:
            self._response(
                self._start_response(307),
                headers={'Location': '/method/%s' % self._method.lower()})
        else:
            self._response(
                self._start_response(307),
                headers={'Location': self._path})

    @test_utils.Router.define('/encoding/(gzip|deflate)$')
    def encoding(self, match):
        mode = match.group(1)

        resp = self._start_response(200)
        resp.add_compression_filter(mode)
        resp.add_chunking_filter(100)
        self._response(resp, headers={'Content-encoding': mode}, chunked=True)

    @test_utils.Router.define('/chunked$')
    def chunked(self, match):
        resp = self._start_response(200)
        resp.add_chunking_filter(100)
        self._response(resp, chunked=True)

    @test_utils.Router.define('/keepalive$')
    def keepalive(self, match):
        self._transport._requests = getattr(
            self._transport, '_requests', 0) + 1
        resp = self._start_response(200)
        if 'close=' in self._query:
            self._response(
                resp, 'requests={}'.format(self._transport._requests))
        else:
            self._response(
                resp, 'requests={}'.format(self._transport._requests),
                headers={'CONNECTION': 'keep-alive'})

    @test_utils.Router.define('/cookies$')
    def cookies(self, match):
        cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'cookie1'
        cookies['c2'] = 'cookie2'

        resp = self._start_response(200)
        for cookie in cookies.output(header='').split('\n'):
            resp.add_header('Set-Cookie', cookie.strip())

        resp.add_header(
            'Set-Cookie',
            'ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}='
            '{925EC0B8-CB17-4BEB-8A35-1033813B0523}; HttpOnly; Path=/')
        self._response(resp)

    @test_utils.Router.define('/cookies_partial$')
    def cookies_partial(self, match):
        cookies = http.cookies.SimpleCookie()
        cookies['c1'] = 'other_cookie1'

        resp = self._start_response(200)
        for cookie in cookies.output(header='').split('\n'):
            resp.add_header('Set-Cookie', cookie.strip())

        self._response(resp)

    @test_utils.Router.define('/broken$')
    def broken(self, match):
        resp = self._start_response(200)

        def write_body(resp, body):
            self._transport.close()
            raise ValueError()

        self._response(
            resp,
            body=json.dumps({'t': (b'0' * 1024).decode('utf-8')}),
            write_body=write_body)
