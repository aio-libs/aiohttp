"""Tests for http/wsgi.py"""

import io
import asyncio
import unittest
import unittest.mock

import aiohttp
from aiohttp import multidict
from aiohttp import wsgi
from aiohttp import protocol


class TestHttpWsgiServerProtocol(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.wsgi = unittest.mock.Mock()
        self.reader = unittest.mock.Mock()
        self.writer = unittest.mock.Mock()
        self.writer.drain.return_value = ()
        self.transport = unittest.mock.Mock()
        self.transport.get_extra_info.side_effect = [('1.2.3.4', 1234),
                                                     ('2.3.4.5', 80)]

        self.headers = multidict.MultiDict({"HOST": "python.org"})
        self.message = protocol.RawRequestMessage(
            'GET', '/path', (1, 0), self.headers, True, 'deflate')
        self.payload = aiohttp.FlowControlDataQueue(self.reader)
        self.payload.feed_data(b'data', 4)
        self.payload.feed_data(b'data', 4)
        self.payload.feed_eof()

    def tearDown(self):
        self.loop.close()

    def test_ctor(self):
        srv = wsgi.WSGIServerHttpProtocol(self.wsgi, loop=self.loop)
        self.assertIs(srv.wsgi, self.wsgi)
        self.assertFalse(srv.readpayload)

    def _make_one(self, **kw):
        srv = wsgi.WSGIServerHttpProtocol(self.wsgi, loop=self.loop, **kw)
        srv.reader = self.reader
        srv.writer = self.writer
        srv.transport = self.transport
        return srv.create_wsgi_environ(self.message, self.payload)

    def _make_srv(self, app=None, **kw):
        if app is None:
            app = self.wsgi
        srv = wsgi.WSGIServerHttpProtocol(app, loop=self.loop, **kw)
        srv.reader = self.reader
        srv.writer = self.writer
        srv.transport = self.transport
        return srv

    def test_environ(self):
        environ = self._make_one()
        self.assertEqual(environ['RAW_URI'], '/path')
        self.assertEqual(environ['wsgi.async'], True)

    def test_environ_headers(self):
        self.headers.extend(
            (('SCRIPT_NAME', 'script'),
             ('CONTENT-TYPE', 'text/plain'),
             ('CONTENT-LENGTH', '209'),
             ('X_TEST', '123'),
             ('X_TEST', '456')))
        environ = self._make_one()
        self.assertEqual(environ['CONTENT_TYPE'], 'text/plain')
        self.assertEqual(environ['CONTENT_LENGTH'], '209')
        self.assertEqual(environ['HTTP_X_TEST'], '123,456')
        self.assertEqual(environ['SCRIPT_NAME'], 'script')
        self.assertEqual(environ['SERVER_NAME'], 'python.org')
        self.assertEqual(environ['SERVER_PORT'], '80')
        get_extra_info_calls = self.transport.get_extra_info.mock_calls
        expected_calls = [
            unittest.mock.call('peername'),
            unittest.mock.call('sockname'),
        ]
        self.assertEqual(expected_calls, get_extra_info_calls)

    def test_environ_host_header_alternate_port(self):
        self.transport.get_extra_info = unittest.mock.Mock(
            side_effect=[('1.2.3.4', 1234), ('3.4.5.6', 82)]
        )
        self.headers.update({'HOST': 'example.com:9999'})
        environ = self._make_one()
        self.assertEqual(environ['SERVER_PORT'], '82')

    def test_environ_host_header_alternate_port_ssl(self):
        self.transport.get_extra_info = unittest.mock.Mock(
            side_effect=[('1.2.3.4', 1234), ('3.4.5.6', 82)]
        )
        self.headers.update({'HOST': 'example.com:9999'})
        environ = self._make_one(is_ssl=True)
        self.assertEqual(environ['SERVER_PORT'], '82')

    def test_wsgi_response(self):
        srv = self._make_srv()
        resp = srv.create_wsgi_response(self.message)
        self.assertIsInstance(resp, wsgi.WsgiResponse)

    def test_wsgi_response_start_response(self):
        srv = self._make_srv()
        resp = srv.create_wsgi_response(self.message)
        resp.start_response(
            '200 OK', [('CONTENT-TYPE', 'text/plain')])
        self.assertEqual(resp.status, '200 OK')
        self.assertIsInstance(resp.response, protocol.Response)

    def test_wsgi_response_start_response_exc(self):
        srv = self._make_srv()
        resp = srv.create_wsgi_response(self.message)
        resp.start_response(
            '200 OK', [('CONTENT-TYPE', 'text/plain')], ['', ValueError()])
        self.assertEqual(resp.status, '200 OK')
        self.assertIsInstance(resp.response, protocol.Response)

    def test_wsgi_response_start_response_exc_status(self):
        srv = self._make_srv()
        resp = srv.create_wsgi_response(self.message)
        resp.start_response('200 OK', [('CONTENT-TYPE', 'text/plain')])

        self.assertRaises(
            ValueError,
            resp.start_response,
            '500 Err', [('CONTENT-TYPE', 'text/plain')], ['', ValueError()])

    @unittest.mock.patch('aiohttp.wsgi.aiohttp')
    def test_wsgi_response_101_upgrade_to_websocket(self, m_asyncio):
        srv = self._make_srv()
        resp = srv.create_wsgi_response(self.message)
        resp.start_response(
            '101 Switching Protocols', (('UPGRADE', 'websocket'),
                                        ('CONNECTION', 'upgrade')))
        self.assertEqual(resp.status, '101 Switching Protocols')
        self.assertTrue(m_asyncio.Response.return_value.send_headers.called)

    def test_file_wrapper(self):
        fobj = io.BytesIO(b'data')
        wrapper = wsgi.FileWrapper(fobj, 2)
        self.assertIs(wrapper, iter(wrapper))
        self.assertTrue(hasattr(wrapper, 'close'))

        self.assertEqual(next(wrapper), b'da')
        self.assertEqual(next(wrapper), b'ta')
        self.assertRaises(StopIteration, next, wrapper)

        wrapper = wsgi.FileWrapper(b'data', 2)
        self.assertFalse(hasattr(wrapper, 'close'))

    def test_handle_request_futures(self):

        def wsgi_app(env, start):
            start('200 OK', [('Content-Type', 'text/plain')])
            f1 = asyncio.Future(loop=self.loop)
            f1.set_result(b'data')
            fut = asyncio.Future(loop=self.loop)
            fut.set_result([f1])
            return fut

        srv = self._make_srv(wsgi_app)
        self.loop.run_until_complete(
            srv.handle_request(self.message, self.payload))

        content = b''.join(
            [c[1][0] for c in self.writer.write.mock_calls])
        self.assertTrue(content.startswith(b'HTTP/1.0 200 OK'))
        self.assertTrue(content.endswith(b'data'))

    def test_handle_request_simple(self):

        def wsgi_app(env, start):
            start('200 OK', [('Content-Type', 'text/plain')])
            return [b'data']

        stream = asyncio.StreamReader(loop=self.loop)
        stream.feed_data(b'data')
        stream.feed_eof()

        self.message = protocol.RawRequestMessage(
            'GET', '/path', (1, 1), self.headers, True, 'deflate')

        srv = self._make_srv(wsgi_app, readpayload=True)
        self.loop.run_until_complete(
            srv.handle_request(self.message, self.payload))

        content = b''.join(
            [c[1][0] for c in self.writer.write.mock_calls])
        self.assertTrue(content.startswith(b'HTTP/1.1 200 OK'))
        self.assertTrue(content.endswith(b'data\r\n0\r\n\r\n'))
        self.assertFalse(srv._keep_alive)

    def test_handle_request_io(self):

        def wsgi_app(env, start):
            start('200 OK', [('Content-Type', 'text/plain')])
            return io.BytesIO(b'data')

        srv = self._make_srv(wsgi_app)

        self.loop.run_until_complete(
            srv.handle_request(self.message, self.payload))

        content = b''.join(
            [c[1][0] for c in self.writer.write.mock_calls])
        self.assertTrue(content.startswith(b'HTTP/1.0 200 OK'))
        self.assertTrue(content.endswith(b'data'))

    def test_handle_request_keep_alive(self):

        def wsgi_app(env, start):
            start('200 OK', [('Content-Type', 'text/plain')])
            return [b'data']

        stream = asyncio.StreamReader(loop=self.loop)
        stream.feed_data(b'data')
        stream.feed_eof()

        self.message = protocol.RawRequestMessage(
            'GET', '/path', (1, 1), self.headers, False, 'deflate')

        srv = self._make_srv(wsgi_app, readpayload=True)

        self.loop.run_until_complete(
            srv.handle_request(self.message, self.payload))

        content = b''.join(
            [c[1][0] for c in self.writer.write.mock_calls])
        self.assertTrue(content.startswith(b'HTTP/1.1 200 OK'))
        self.assertTrue(content.endswith(b'data\r\n0\r\n\r\n'))
        self.assertTrue(srv._keep_alive)

    def test_handle_request_readpayload(self):

        def wsgi_app(env, start):
            start('200 OK', [('Content-Type', 'text/plain')])
            return [env['wsgi.input'].read()]

        srv = self._make_srv(wsgi_app, readpayload=True)

        self.loop.run_until_complete(
            srv.handle_request(self.message, self.payload))

        content = b''.join(
            [c[1][0] for c in self.writer.write.mock_calls])
        self.assertTrue(content.startswith(b'HTTP/1.0 200 OK'))
        self.assertTrue(content.endswith(b'data'))

    def test_dont_unquote_environ_path_info(self):
        path = '/path/some%20text'
        self.message = protocol.RawRequestMessage(
            'GET', path, (1, 0), self.headers, True, 'deflate')
        environ = self._make_one()
        self.assertEqual(environ['PATH_INFO'], path)

    def test_not_add_authorization(self):
        self.headers.extend({'AUTHORIZATION': 'spam',
                             'X-CUSTOM-HEADER': 'eggs'})
        self.message = protocol.RawRequestMessage(
            'GET', '/', (1, 1), self.headers, True, 'deflate')
        environ = self._make_one()
        self.assertEqual('eggs', environ['HTTP_X_CUSTOM_HEADER'])
        self.assertFalse('AUTHORIZATION' in environ)

    def test_http_1_0_no_host(self):
        headers = multidict.MultiDict({})
        self.message = protocol.RawRequestMessage(
            'GET', '/', (1, 0), headers, True, 'deflate')
        environ = self._make_one()
        self.assertEqual(environ['SERVER_NAME'], '2.3.4.5')
        self.assertEqual(environ['SERVER_PORT'], '80')
