"""Tests for aiohttp/server.py"""

import asyncio
import socket
import unittest
import unittest.mock

from html import escape

from aiohttp import server
from aiohttp import errors
from aiohttp import test_utils


class TestHttpServerProtocol(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()

    def test_http_error_exception(self):
        exc = errors.HttpProcessingError(code=500, message='Internal error')
        self.assertEqual(exc.code, 500)
        self.assertEqual(exc.message, 'Internal error')

    def test_handle_request(self):
        transport = unittest.mock.Mock()

        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)
        srv.writer = unittest.mock.Mock()

        message = unittest.mock.Mock()
        message.headers = []
        message.version = (1, 1)
        srv.handle_request(message, unittest.mock.Mock())

        content = b''.join(
            [c[1][0] for c in list(srv.writer.write.mock_calls)])
        self.assertTrue(content.startswith(b'HTTP/1.1 404 Not Found\r\n'))

    def test_closing(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv._keep_alive = True

        keep_alive_handle = unittest.mock.Mock()
        srv._keep_alive_handle = keep_alive_handle
        timeout_handle = unittest.mock.Mock()
        srv._timeout_handle = timeout_handle
        transport = srv.transport = unittest.mock.Mock()
        request_handler = srv._request_handler = unittest.mock.Mock()
        srv.writer = unittest.mock.Mock()

        srv.closing()
        self.assertTrue(transport.close.called)
        self.assertIsNone(srv.transport)

        self.assertIsNotNone(srv._keep_alive_handle)
        self.assertFalse(keep_alive_handle.cancel.called)

        self.assertIsNotNone(srv._timeout_handle)
        self.assertFalse(timeout_handle.cancel.called)

        self.assertIsNone(srv._request_handler)
        self.assertTrue(request_handler.cancel.called)

    def test_closing_during_reading(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv._keep_alive = True
        srv._keep_alive_on = True
        srv._reading_request = True
        srv._timeout_handle = timeout_handle = unittest.mock.Mock()
        transport = srv.transport = unittest.mock.Mock()

        srv.closing()
        self.assertFalse(transport.close.called)
        self.assertIsNotNone(srv.transport)

        # cancel existing slow request handler
        self.assertIsNotNone(srv._timeout_handle)
        self.assertTrue(timeout_handle.cancel.called)
        self.assertIsNot(timeout_handle, srv._timeout_handle)

    def test_double_closing(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv._keep_alive = True

        keep_alive_handle = unittest.mock.Mock()
        srv._keep_alive_handle = keep_alive_handle
        timeout_handle = unittest.mock.Mock()
        srv._timeout_handle = timeout_handle
        transport = srv.transport = unittest.mock.Mock()
        srv.writer = unittest.mock.Mock()

        srv.closing()
        self.assertTrue(transport.close.called)
        self.assertIsNone(srv.transport)

        transport.reset_mock()
        srv.closing()
        self.assertFalse(transport.close.called)
        self.assertIsNone(srv.transport)

        self.assertIsNotNone(srv._keep_alive_handle)
        self.assertFalse(keep_alive_handle.cancel.called)

        self.assertIsNotNone(srv._timeout_handle)
        self.assertFalse(timeout_handle.cancel.called)

    def test_connection_made(self):
        srv = server.ServerHttpProtocol(loop=self.loop, timeout=15)
        self.assertIsNone(srv._request_handler)

        srv.connection_made(unittest.mock.Mock())
        self.assertIsNotNone(srv._request_handler)
        self.assertIsNotNone(srv._timeout_handle)

    def test_connection_made_without_timeout(self):
        srv = server.ServerHttpProtocol(loop=self.loop, timeout=0)

        srv.connection_made(unittest.mock.Mock())
        self.assertIsNone(srv._timeout_handle)

    def test_connection_made_with_keepaplive(self):
        srv = server.ServerHttpProtocol(loop=self.loop)

        sock = unittest.mock.Mock()
        transport = unittest.mock.Mock()
        transport.get_extra_info.return_value = sock
        srv.connection_made(transport)
        sock.setsockopt.assert_called_with(socket.SOL_SOCKET,
                                           socket.SO_KEEPALIVE, 1)

    def test_connection_made_without_keepaplive(self):
        srv = server.ServerHttpProtocol(loop=self.loop, keep_alive_on=False)

        sock = unittest.mock.Mock()
        transport = unittest.mock.Mock()
        transport.get_extra_info.return_value = sock
        srv.connection_made(transport)
        self.assertFalse(sock.setsockopt.called)

    def test_data_received(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(unittest.mock.Mock())

        srv.data_received(b'123')
        self.assertEqual(b'123', bytes(srv.reader._buffer))

        srv.data_received(b'456')
        self.assertEqual(b'123456', bytes(srv.reader._buffer))

    def test_eof_received(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(unittest.mock.Mock())
        srv.eof_received()
        self.assertTrue(srv.reader._eof)

    def test_connection_lost(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(unittest.mock.Mock())
        srv.data_received(b'123')

        timeout_handle = srv._timeout_handle = unittest.mock.Mock()
        keep_alive_handle = srv._keep_alive_handle = unittest.mock.Mock()

        handle = srv._request_handler
        srv.connection_lost(None)
        test_utils.run_briefly(self.loop)

        self.assertIsNone(srv._request_handler)
        self.assertTrue(handle.cancelled())

        self.assertIsNone(srv._keep_alive_handle)
        self.assertTrue(keep_alive_handle.cancel.called)

        self.assertIsNone(srv._timeout_handle)
        self.assertTrue(timeout_handle.cancel.called)

        srv.connection_lost(None)
        self.assertIsNone(srv._request_handler)
        self.assertIsNone(srv._keep_alive_handle)

    def test_srv_keep_alive(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        self.assertFalse(srv._keep_alive)

        srv.keep_alive(True)
        self.assertTrue(srv._keep_alive)

        srv.keep_alive(False)
        self.assertFalse(srv._keep_alive)

    def test_srv_slow_request(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(timeout=0.01, loop=self.loop)
        srv.connection_made(transport)

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(transport.close.called)
        srv.connection_lost(None)
        self.assertIsNone(srv._timeout_handle)

    def test_bad_method(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)

        srv.reader.feed_data(
            b'!@#$ / HTTP/1.0\r\n'
            b'Host: example.com\r\n\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(transport.write.mock_calls[0][1][0].startswith(
            b'HTTP/1.1 400 Bad Request\r\n'))

    def test_line_too_long(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)

        srv.reader.feed_data(b''.join([b'a' for _ in range(10000)]))

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(transport.write.mock_calls[0][1][0].startswith(
            b'HTTP/1.1 400 Bad Request\r\n'))

    def test_handle_error(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)
        srv.keep_alive(True)
        srv.writer = unittest.mock.Mock()

        srv.handle_error(404, headers=(('X-Server', 'asyncio'),))
        content = b''.join(
            [c[1][0] for c in list(srv.writer.write.mock_calls)])
        self.assertIn(b'HTTP/1.1 404 Not Found', content)
        self.assertIn(b'X-SERVER: asyncio', content)
        self.assertFalse(srv._keep_alive)

    def test_handle_error__utf(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(debug=True, loop=self.loop)
        srv.connection_made(transport)
        srv.keep_alive(True)
        srv.writer = unittest.mock.Mock()
        srv.logger = unittest.mock.Mock()

        try:
            raise RuntimeError('что-то пошло не так')
        except RuntimeError as exc:
            srv.handle_error(exc=exc)
        content = b''.join(
            [c[1][0] for c in list(srv.writer.write.mock_calls)])
        self.assertIn(b'HTTP/1.1 500 Internal Server Error', content)
        self.assertIn(b'CONTENT-TYPE: text/html; charset=utf-8', content)
        pattern = escape("raise RuntimeError('что-то пошло не так')")
        self.assertIn(pattern.encode('utf-8'), content)
        self.assertFalse(srv._keep_alive)

        srv.logger.exception.assert_called_with("Error handling request")

    @unittest.mock.patch('aiohttp.server.traceback')
    def test_handle_error_traceback_exc(self, m_trace):
        log = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(debug=True, logger=log, loop=self.loop)
        srv.transport = unittest.mock.Mock()
        srv.transport.get_extra_info.return_value = '127.0.0.1'
        srv.writer = unittest.mock.Mock()
        srv._request_handler = object()

        m_trace.format_exc.side_effect = ValueError

        srv.handle_error(500, exc=object())
        content = b''.join(
            [c[1][0] for c in list(srv.writer.write.mock_calls)])
        self.assertTrue(
            content.startswith(b'HTTP/1.1 500 Internal Server Error'))
        self.assertTrue(log.exception.called)

    def test_handle_error_debug(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.debug = True
        srv.connection_made(transport)
        srv.writer = unittest.mock.Mock()

        try:
            raise ValueError()
        except Exception as exc:
            srv.handle_error(999, exc=exc)

        content = b''.join(
            [c[1][0] for c in list(srv.writer.write.mock_calls)])

        self.assertIn(b'HTTP/1.1 500 Internal', content)
        self.assertIn(b'Traceback (most recent call last):', content)

    def test_handle_error_500(self):
        log = unittest.mock.Mock()
        transport = unittest.mock.Mock()

        srv = server.ServerHttpProtocol(logger=log, loop=self.loop)
        srv.connection_made(transport)
        srv.writer = unittest.mock.Mock()

        srv.handle_error(500)
        self.assertTrue(log.exception.called)

    def test_handle(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)

        handle = srv.handle_request = unittest.mock.Mock()

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(handle.called)
        self.assertTrue(transport.close.called)

    def test_handle_uncompleted(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)
        srv.logger.exception = unittest.mock.Mock()

        handle = srv.handle_request = unittest.mock.Mock()
        handle.side_effect = ValueError

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n'
            b'Content-Length: 50000\r\n\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(handle.called)
        self.assertTrue(transport.close.called)
        srv.logger.exception.assert_called_with("Error handling request")

    def test_handle_coro(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)

        called = False

        @asyncio.coroutine
        def coro(message, payload):
            nonlocal called
            called = True
            srv.eof_received()

        srv.handle_request = coro
        srv.connection_made(transport)

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n\r\n')
        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(called)

    def test_handle_cancel(self):
        log = unittest.mock.Mock()
        transport = unittest.mock.Mock()

        srv = server.ServerHttpProtocol(logger=log, debug=True, loop=self.loop)
        srv.connection_made(transport)
        srv.writer = unittest.mock.Mock()
        srv.handle_request = unittest.mock.Mock()

        @asyncio.coroutine
        def cancel():
            srv._request_handler.cancel()

        self.loop.run_until_complete(
            asyncio.wait([srv._request_handler, cancel()], loop=self.loop))
        self.assertTrue(log.debug.called)

    def test_handle_cancelled(self):
        log = unittest.mock.Mock()
        transport = unittest.mock.Mock()

        srv = server.ServerHttpProtocol(logger=log, debug=True, loop=self.loop)
        srv.connection_made(transport)

        srv.handle_request = unittest.mock.Mock()
        test_utils.run_briefly(self.loop)  # start request_handler task

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n\r\n')

        r_handler = srv._request_handler
        srv._request_handler = None  # emulate srv.connection_lost()

        self.assertIsNone(self.loop.run_until_complete(r_handler))

    def test_handle_400(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)
        srv.handle_error = unittest.mock.Mock()
        srv.keep_alive(True)
        srv.reader.feed_data(b'GET / HT/asd\r\n\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(srv.handle_error.called)
        self.assertEqual(400, srv.handle_error.call_args[0][0])
        self.assertTrue(transport.close.called)

    def test_handle_500(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.connection_made(transport)

        handle = srv.handle_request = unittest.mock.Mock()
        handle.side_effect = ValueError
        srv.handle_error = unittest.mock.Mock()

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n\r\n')
        self.loop.run_until_complete(srv._request_handler)

        self.assertTrue(srv.handle_error.called)
        self.assertEqual(500, srv.handle_error.call_args[0][0])

    def test_handle_error_no_handle_task(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.keep_alive(True)
        srv.connection_made(transport)
        srv.connection_lost(None)

        srv.handle_error(300)
        self.assertFalse(srv._keep_alive)

    def test_keep_alive(self):
        srv = server.ServerHttpProtocol(keep_alive=0.1, loop=self.loop)
        transport = unittest.mock.Mock()
        closed = False

        def close():
            nonlocal closed
            closed = True
            srv.connection_lost(None)
            self.loop.stop()

        transport.close = close

        srv.connection_made(transport)

        handle = srv.handle_request = unittest.mock.Mock()

        srv.reader.feed_data(
            b'GET / HTTP/1.1\r\n'
            b'CONNECTION: keep-alive\r\n'
            b'HOST: example.com\r\n\r\n')

        self.loop.run_forever()
        self.assertTrue(handle.called)
        self.assertTrue(closed)

    def test_keep_alive_close_existing(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(keep_alive=0, loop=self.loop)
        srv.connection_made(transport)
        self.assertIsNone(srv._keep_alive_handle)

        srv._keep_alive_period = 15
        keep_alive_handle = srv._keep_alive_handle = unittest.mock.Mock()
        srv.handle_request = unittest.mock.Mock()
        srv.handle_request.return_value = asyncio.Future(loop=self.loop)
        srv.handle_request.return_value.set_result(1)

        srv.data_received(
            b'GET / HTTP/1.0\r\n'
            b'HOST: example.com\r\n\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(keep_alive_handle.cancel.called)
        self.assertIsNone(srv._keep_alive_handle)
        self.assertTrue(transport.close.called)

    def test_log_access_error(self):
        transport = unittest.mock.Mock()
        transport.get_extra_info.return_value = '127.0.0.1'

        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.transport = transport
        srv.logger = unittest.mock.Mock()
        srv.access_log = unittest.mock.Mock()

        message = unittest.mock.Mock()
        message.headers = []
        message.version = (1, 1)
        srv.log_access(None, None, None, None)

        self.assertTrue(srv.logger.error.called)

    def test_log_access_disabled(self):
        transport = unittest.mock.Mock()

        srv = server.ServerHttpProtocol(loop=self.loop, access_log=None)
        srv.connection_made(transport)
        srv.logger = unittest.mock.Mock()

        message = unittest.mock.Mock()
        message.headers = []
        message.version = (1, 1)
        srv.log_access(None, None, None, None)

        self.assertFalse(srv.logger.error.called)

    def test_cancel_not_connected_handler(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        srv.cancel_slow_request()

    def test_srv_process_request_without_timeout(self):
        transport = unittest.mock.Mock()
        srv = server.ServerHttpProtocol(timeout=0, loop=self.loop)
        srv.connection_made(transport)
        self.assertIsNone(srv._timeout_handle)

        srv.reader.feed_data(
            b'GET / HTTP/1.0\r\n'
            b'Host: example.com\r\n\r\n')

        self.loop.run_until_complete(srv._request_handler)
        self.assertTrue(transport.close.called)
        self.assertIsNone(srv._timeout_handle)

    def test_keep_alive_timeout_default(self):
        srv = server.ServerHttpProtocol(loop=self.loop)
        self.assertEqual(75, srv.keep_alive_timeout)

    def test_keep_alive_timeout_nondefault(self):
        srv = server.ServerHttpProtocol(loop=self.loop, keep_alive=10)
        self.assertEqual(10, srv.keep_alive_timeout)
