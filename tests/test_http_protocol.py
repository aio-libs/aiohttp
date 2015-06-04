"""Tests for aiohttp/protocol.py"""

import unittest
import unittest.mock
import asyncio
import zlib

from aiohttp import hdrs, protocol


class TestHttpMessage(unittest.TestCase):

    def setUp(self):
        self.transport = unittest.mock.Mock()
        asyncio.set_event_loop(None)

    def test_start_request(self):
        msg = protocol.Request(
            self.transport, 'GET', '/index.html', close=True)

        self.assertIs(msg.transport, self.transport)
        self.assertIsNone(msg.status)
        self.assertTrue(msg.closing)
        self.assertEqual(msg.status_line, 'GET /index.html HTTP/1.1\r\n')

    def test_start_response(self):
        msg = protocol.Response(self.transport, 200, close=True)

        self.assertIs(msg.transport, self.transport)
        self.assertEqual(msg.status, 200)
        self.assertEqual(msg.reason, "OK")
        self.assertTrue(msg.closing)
        self.assertEqual(msg.status_line, 'HTTP/1.1 200 OK\r\n')

    def test_start_response_with_reason(self):
        msg = protocol.Response(self.transport, 333, close=True,
                                reason="My Reason")

        self.assertEqual(msg.status, 333)
        self.assertEqual(msg.reason, "My Reason")
        self.assertEqual(msg.status_line, 'HTTP/1.1 333 My Reason\r\n')

    def test_start_response_with_unknown_reason(self):
        msg = protocol.Response(self.transport, 777, close=True)

        self.assertEqual(msg.status, 777)
        self.assertEqual(msg.reason, "777")
        self.assertEqual(msg.status_line, 'HTTP/1.1 777 777\r\n')

    def test_force_close(self):
        msg = protocol.Response(self.transport, 200)
        self.assertFalse(msg.closing)
        msg.force_close()
        self.assertTrue(msg.closing)

    def test_force_chunked(self):
        msg = protocol.Response(self.transport, 200)
        self.assertFalse(msg.chunked)
        msg.enable_chunked_encoding()
        self.assertTrue(msg.chunked)

    def test_keep_alive(self):
        msg = protocol.Response(self.transport, 200, close=True)
        self.assertFalse(msg.keep_alive())
        msg.keepalive = True
        self.assertTrue(msg.keep_alive())

        msg.force_close()
        self.assertFalse(msg.keep_alive())

    def test_keep_alive_http10(self):
        msg = protocol.Response(self.transport, 200, http_version=(1, 0))
        self.assertFalse(msg.keepalive)
        self.assertFalse(msg.keep_alive())

        msg = protocol.Response(self.transport, 200, http_version=(1, 1))
        self.assertIsNone(msg.keepalive)

    def test_add_header(self):
        msg = protocol.Response(self.transport, 200)
        self.assertEqual([], list(msg.headers))

        msg.add_header('content-type', 'plain/html')
        self.assertEqual(
            [('CONTENT-TYPE', 'plain/html')], list(msg.headers.items()))

    def test_add_header_with_spaces(self):
        msg = protocol.Response(self.transport, 200)
        self.assertEqual([], list(msg.headers))

        msg.add_header('content-type', '  plain/html  ')
        self.assertEqual(
            [('CONTENT-TYPE', 'plain/html')], list(msg.headers.items()))

    def test_add_header_non_ascii(self):
        msg = protocol.Response(self.transport, 200)
        self.assertEqual([], list(msg.headers))

        with self.assertRaises(AssertionError):
            msg.add_header('тип-контента', 'текст/плейн')

    def test_add_header_invalid_value_type(self):
        msg = protocol.Response(self.transport, 200)
        self.assertEqual([], list(msg.headers))

        with self.assertRaises(AssertionError):
            msg.add_header('content-type', {'test': 'plain'})

        with self.assertRaises(AssertionError):
            msg.add_header(list('content-type'), 'text/plain')

    def test_add_headers(self):
        msg = protocol.Response(self.transport, 200)
        self.assertEqual([], list(msg.headers))

        msg.add_headers(('content-type', 'plain/html'))
        self.assertEqual(
            [('CONTENT-TYPE', 'plain/html')], list(msg.headers.items()))

    def test_add_headers_length(self):
        msg = protocol.Response(self.transport, 200)
        self.assertIsNone(msg.length)

        msg.add_headers(('content-length', '42'))
        self.assertEqual(42, msg.length)

    def test_add_headers_upgrade(self):
        msg = protocol.Response(self.transport, 200)
        self.assertFalse(msg.upgrade)

        msg.add_headers(('connection', 'upgrade'))
        self.assertTrue(msg.upgrade)

    def test_add_headers_upgrade_websocket(self):
        msg = protocol.Response(self.transport, 200)

        msg.add_headers(('upgrade', 'test'))
        self.assertEqual([], list(msg.headers))

        msg.add_headers(('upgrade', 'websocket'))
        self.assertEqual(
            [('UPGRADE', 'websocket')], list(msg.headers.items()))

    def test_add_headers_connection_keepalive(self):
        msg = protocol.Response(self.transport, 200)

        msg.add_headers(('connection', 'keep-alive'))
        self.assertEqual([], list(msg.headers))
        self.assertTrue(msg.keepalive)

        msg.add_headers(('connection', 'close'))
        self.assertFalse(msg.keepalive)

    def test_add_headers_hop_headers(self):
        msg = protocol.Response(self.transport, 200)
        msg.HOP_HEADERS = (hdrs.TRANSFER_ENCODING,)

        msg.add_headers(('connection', 'test'), ('transfer-encoding', 't'))
        self.assertEqual([], list(msg.headers))

    def test_default_headers(self):
        msg = protocol.Response(self.transport, 200)
        msg._add_default_headers()

        headers = [r for r, _ in msg.headers.items()]
        self.assertIn('DATE', headers)
        self.assertIn('CONNECTION', headers)

    def test_default_headers_server(self):
        msg = protocol.Response(self.transport, 200)
        msg._add_default_headers()

        self.assertIn('SERVER', msg.headers)

    def test_default_headers_useragent(self):
        msg = protocol.Request(self.transport, 'GET', '/')
        msg._add_default_headers()

        self.assertNotIn('SERVER', msg.headers)
        self.assertIn('USER-AGENT', msg.headers)

    def test_default_headers_useragent_custom(self):
        msg = protocol.Request(self.transport, 'GET', '/')
        msg.add_headers(('user-agent', 'my custom agent'))
        msg._add_default_headers()

        headers = [r for r, _ in msg.headers.items()
                   if r.lower() == 'user-agent']
        self.assertEqual(len(headers), 1)

    def test_default_headers_chunked(self):
        msg = protocol.Response(self.transport, 200)
        msg._add_default_headers()

        headers = [r for r, _ in msg.headers.items()]
        self.assertNotIn('TRANSFER-ENCODING', headers)

        msg = protocol.Response(self.transport, 200)
        msg.enable_chunked_encoding()
        msg.send_headers()

        headers = [r for r, _ in msg.headers.items()]
        self.assertIn('TRANSFER-ENCODING', headers)

    def test_default_headers_connection_upgrade(self):
        msg = protocol.Response(self.transport, 200)
        msg.upgrade = True
        msg._add_default_headers()

        headers = [r for r in msg.headers.items() if r[0] == 'CONNECTION']
        self.assertEqual([('CONNECTION', 'upgrade')], headers)

    def test_default_headers_connection_close(self):
        msg = protocol.Response(self.transport, 200)
        msg.force_close()
        msg._add_default_headers()

        headers = [r for r in msg.headers.items() if r[0] == 'CONNECTION']
        self.assertEqual([('CONNECTION', 'close')], headers)

    def test_default_headers_connection_keep_alive(self):
        msg = protocol.Response(self.transport, 200)
        msg.keepalive = True
        msg._add_default_headers()

        headers = [r for r in msg.headers.items() if r[0] == 'CONNECTION']
        self.assertEqual([('CONNECTION', 'keep-alive')], headers)

    def test_send_headers(self):
        write = self.transport.write = unittest.mock.Mock()

        msg = protocol.Response(self.transport, 200)
        msg.add_headers(('content-type', 'plain/html'))
        self.assertFalse(msg.is_headers_sent())

        msg.send_headers()

        content = b''.join([arg[1][0] for arg in list(write.mock_calls)])

        self.assertTrue(content.startswith(b'HTTP/1.1 200 OK\r\n'))
        self.assertIn(b'CONTENT-TYPE: plain/html', content)
        self.assertTrue(msg.headers_sent)
        self.assertTrue(msg.is_headers_sent())
        # cleanup
        msg.writer.close()

    def test_send_headers_non_ascii(self):
        write = self.transport.write = unittest.mock.Mock()

        msg = protocol.Response(self.transport, 200)
        msg.add_headers(('x-header', 'текст'))
        self.assertFalse(msg.is_headers_sent())

        msg.send_headers()

        content = b''.join([arg[1][0] for arg in list(write.mock_calls)])

        self.assertTrue(content.startswith(b'HTTP/1.1 200 OK\r\n'))
        self.assertIn(b'X-HEADER: \xd1\x82\xd0\xb5\xd0\xba\xd1\x81\xd1\x82',
                      content)
        self.assertTrue(msg.headers_sent)
        self.assertTrue(msg.is_headers_sent())
        # cleanup
        msg.writer.close()

    def test_send_headers_nomore_add(self):
        msg = protocol.Response(self.transport, 200)
        msg.add_headers(('content-type', 'plain/html'))
        msg.send_headers()

        self.assertRaises(AssertionError,
                          msg.add_header, 'content-type', 'plain/html')
        # cleanup
        msg.writer.close()

    def test_prepare_length(self):
        msg = protocol.Response(self.transport, 200)
        w_l_p = msg._write_length_payload = unittest.mock.Mock()
        w_l_p.return_value = iter([1, 2, 3])

        msg.add_headers(('content-length', '42'))
        msg.send_headers()

        self.assertTrue(w_l_p.called)
        self.assertEqual((42,), w_l_p.call_args[0])

    def test_prepare_chunked_force(self):
        msg = protocol.Response(self.transport, 200)
        msg.enable_chunked_encoding()

        chunked = msg._write_chunked_payload = unittest.mock.Mock()
        chunked.return_value = iter([1, 2, 3])

        msg.add_headers(('content-length', '42'))
        msg.send_headers()
        self.assertTrue(chunked.called)

    def test_prepare_chunked_no_length(self):
        msg = protocol.Response(self.transport, 200)

        chunked = msg._write_chunked_payload = unittest.mock.Mock()
        chunked.return_value = iter([1, 2, 3])

        msg.send_headers()
        self.assertTrue(chunked.called)

    def test_prepare_eof(self):
        msg = protocol.Response(self.transport, 200, http_version=(1, 0))

        eof = msg._write_eof_payload = unittest.mock.Mock()
        eof.return_value = iter([1, 2, 3])

        msg.send_headers()
        self.assertTrue(eof.called)

    def test_write_auto_send_headers(self):
        msg = protocol.Response(self.transport, 200, http_version=(1, 0))
        msg._send_headers = True

        msg.write(b'data1')
        self.assertTrue(msg.headers_sent)
        # cleanup
        msg.writer.close()

    def test_write_payload_eof(self):
        write = self.transport.write = unittest.mock.Mock()
        msg = protocol.Response(self.transport, 200, http_version=(1, 0))
        msg.send_headers()

        msg.write(b'data1')
        self.assertTrue(msg.headers_sent)

        msg.write(b'data2')
        msg.write_eof()

        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertEqual(
            b'data1data2', content.split(b'\r\n\r\n', 1)[-1])

    def test_write_payload_chunked(self):
        write = self.transport.write = unittest.mock.Mock()

        msg = protocol.Response(self.transport, 200)
        msg.enable_chunked_encoding()
        msg.send_headers()

        msg.write(b'data')
        msg.write_eof()

        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertEqual(
            b'4\r\ndata\r\n0\r\n\r\n',
            content.split(b'\r\n\r\n', 1)[-1])

    def test_write_payload_chunked_multiple(self):
        write = self.transport.write = unittest.mock.Mock()

        msg = protocol.Response(self.transport, 200)
        msg.enable_chunked_encoding()
        msg.send_headers()

        msg.write(b'data1')
        msg.write(b'data2')
        msg.write_eof()

        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertEqual(
            b'5\r\ndata1\r\n5\r\ndata2\r\n0\r\n\r\n',
            content.split(b'\r\n\r\n', 1)[-1])

    def test_write_payload_length(self):
        write = self.transport.write = unittest.mock.Mock()

        msg = protocol.Response(self.transport, 200)
        msg.add_headers(('content-length', '2'))
        msg.send_headers()

        msg.write(b'd')
        msg.write(b'ata')
        msg.write_eof()

        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertEqual(
            b'da', content.split(b'\r\n\r\n', 1)[-1])

    def test_write_payload_chunked_filter(self):
        write = self.transport.write = unittest.mock.Mock()

        msg = protocol.Response(self.transport, 200)
        msg.send_headers()

        msg.add_chunking_filter(2)
        msg.write(b'data')
        msg.write_eof()

        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertTrue(content.endswith(b'2\r\nda\r\n2\r\nta\r\n0\r\n\r\n'))

    def test_write_payload_chunked_filter_mutiple_chunks(self):
        write = self.transport.write = unittest.mock.Mock()
        msg = protocol.Response(self.transport, 200)
        msg.send_headers()

        msg.add_chunking_filter(2)
        msg.write(b'data1')
        msg.write(b'data2')
        msg.write_eof()
        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertTrue(content.endswith(
            b'2\r\nda\r\n2\r\nta\r\n2\r\n1d\r\n2\r\nat\r\n'
            b'2\r\na2\r\n0\r\n\r\n'))

    def test_write_payload_chunked_large_chunk(self):
        write = self.transport.write = unittest.mock.Mock()
        msg = protocol.Response(self.transport, 200)
        msg.send_headers()

        msg.add_chunking_filter(1024)
        msg.write(b'data')
        msg.write_eof()
        content = b''.join([c[1][0] for c in list(write.mock_calls)])
        self.assertTrue(content.endswith(b'4\r\ndata\r\n0\r\n\r\n'))

    _comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    _COMPRESSED = b''.join([_comp.compress(b'data'), _comp.flush()])

    def test_write_payload_deflate_filter(self):
        write = self.transport.write = unittest.mock.Mock()
        msg = protocol.Response(self.transport, 200)
        msg.add_headers(('content-length', '{}'.format(len(self._COMPRESSED))))
        msg.send_headers()

        msg.add_compression_filter('deflate')
        msg.write(b'data')
        msg.write_eof()

        chunks = [c[1][0] for c in list(write.mock_calls)]
        self.assertTrue(all(chunks))
        content = b''.join(chunks)
        self.assertEqual(
            self._COMPRESSED, content.split(b'\r\n\r\n', 1)[-1])

    def test_write_payload_deflate_and_chunked(self):
        write = self.transport.write = unittest.mock.Mock()
        msg = protocol.Response(self.transport, 200)
        msg.send_headers()

        msg.add_compression_filter('deflate')
        msg.add_chunking_filter(2)

        msg.write(b'data')
        msg.write_eof()

        chunks = [c[1][0] for c in list(write.mock_calls)]
        self.assertTrue(all(chunks))
        content = b''.join(chunks)
        self.assertEqual(
            b'2\r\nKI\r\n2\r\n,I\r\n2\r\n\x04\x00\r\n0\r\n\r\n',
            content.split(b'\r\n\r\n', 1)[-1])

    def test_write_payload_chunked_and_deflate(self):
        write = self.transport.write = unittest.mock.Mock()
        msg = protocol.Response(self.transport, 200)
        msg.add_headers(('content-length', '{}'.format(len(self._COMPRESSED))))

        msg.add_chunking_filter(2)
        msg.add_compression_filter('deflate')
        msg.send_headers()

        msg.write(b'data')
        msg.write_eof()

        chunks = [c[1][0] for c in list(write.mock_calls)]
        self.assertTrue(all(chunks))
        content = b''.join(chunks)
        self.assertEqual(
            self._COMPRESSED, content.split(b'\r\n\r\n', 1)[-1])

    def test_write_drain(self):
        msg = protocol.Response(self.transport, 200, http_version=(1, 0))
        msg._send_headers = True

        msg.write(b'1' * (64 * 1024 * 2))
        self.assertFalse(self.transport.drain.called)

        msg.write(b'1', drain=True)
        self.assertTrue(self.transport.drain.called)
        self.assertEqual(msg._output_size, 0)

    def test_dont_override_request_headers_with_default_values(self):
        msg = protocol.Request(
            self.transport, 'GET', '/index.html', close=True)
        msg.add_header('USER-AGENT', 'custom')
        msg._add_default_headers()
        self.assertEqual('custom', msg.headers['USER-AGENT'])

    def test_dont_override_response_headers_with_default_values(self):
        msg = protocol.Response(self.transport, 200, http_version=(1, 0))
        msg.add_header('DATE', 'now')
        msg.add_header('SERVER', 'custom')
        msg._add_default_headers()
        self.assertEqual('custom', msg.headers['SERVER'])
        self.assertEqual('now', msg.headers['DATE'])
