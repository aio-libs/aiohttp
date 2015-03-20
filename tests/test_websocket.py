"""Tests for http/websocket.py"""

import base64
import hashlib
import os
import random
import struct
import unittest
import unittest.mock

import aiohttp
from aiohttp import websocket, multidict, protocol, errors


class WebsocketParserTests(unittest.TestCase):

    def test_parse_frame(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        p.send(struct.pack('!BB', 0b00000001, 0b00000001))
        try:
            p.send(b'1')
        except StopIteration as exc:
            fin, opcode, payload = exc.value

        self.assertEqual((0, 1, b'1'), (fin, opcode, payload))

    def test_parse_frame_length0(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        try:
            p.send(struct.pack('!BB', 0b00000001, 0b00000000))
        except StopIteration as exc:
            fin, opcode, payload = exc.value

        self.assertEqual((0, 1, b''), (fin, opcode, payload))

    def test_parse_frame_length2(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        p.send(struct.pack('!BB', 0b00000001, 126))
        p.send(struct.pack('!H', 4))
        try:
            p.send(b'1234')
        except StopIteration as exc:
            fin, opcode, payload = exc.value

        self.assertEqual((0, 1, b'1234'), (fin, opcode, payload))

    def test_parse_frame_length4(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        p.send(struct.pack('!BB', 0b00000001, 127))
        p.send(struct.pack('!Q', 4))
        try:
            p.send(b'1234')
        except StopIteration as exc:
            fin, opcode, payload = exc.value

        self.assertEqual((0, 1, b'1234'), (fin, opcode, payload))

    def test_parse_frame_mask(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        p.send(struct.pack('!BB', 0b00000001, 0b10000001))
        p.send(b'0001')
        try:
            p.send(b'1')
        except StopIteration as exc:
            fin, opcode, payload = exc.value

        self.assertEqual((0, 1, b'\x01'), (fin, opcode, payload))

    def test_parse_frame_header_reversed_bits(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        self.assertRaises(
            websocket.WebSocketError,
            p.send, struct.pack('!BB', 0b01100000, 0b00000000))

    def test_parse_frame_header_control_frame(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        self.assertRaises(
            websocket.WebSocketError,
            p.send, struct.pack('!BB', 0b00001000, 0b00000000))

    def test_parse_frame_header_continuation(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        self.assertRaises(
            websocket.WebSocketError,
            p.send, struct.pack('!BB', 0b00000000, 0b00000000))

    def test_parse_frame_header_new_data_err(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        self.assertRaises(
            websocket.WebSocketError,
            p.send, struct.pack('!BB', 0b000000000, 0b00000000))

    def test_parse_frame_header_payload_size(self):
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_frame(buf)
        next(p)
        self.assertRaises(
            websocket.WebSocketError,
            p.send, struct.pack('!BB', 0b10001000, 0b01111110))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_ping_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_PING, b'data')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_PING, b'data', ''))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_pong_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_PONG, b'data')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_PONG, b'data', ''))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_close_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CLOSE, b'')
        m_parse_frame.side_effect = parse_frame
        p = websocket.parse_message(aiohttp.ParserBuffer())
        next(p)
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_CLOSE, 0, ''))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_close_frame_info(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CLOSE, b'0112345')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_CLOSE, 12337, b'12345'))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_close_frame_invalid(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CLOSE, b'1')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        self.assertRaises(websocket.WebSocketError, p.send, b'')

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_unknown_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CONTINUATION, b'')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        self.assertRaises(websocket.WebSocketError, p.send, b'')

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_simple_text(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_TEXT, b'text')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_TEXT, 'text', ''))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_simple_binary(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_BINARY, b'binary')
        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_BINARY, b'binary', ''))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation(self, m_parse_frame):
        cur = 0

        def parse_frame(buf):
            nonlocal cur
            yield
            if cur == 0:
                cur = 1
                return (0, websocket.OPCODE_TEXT, b'line1')
            else:
                return (1, websocket.OPCODE_CONTINUATION, b'line2')

        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        p.send(b'')
        try:
            p.send(b'')
        except StopIteration as exc:
            res = exc.value
        self.assertEqual(res, (websocket.OPCODE_TEXT, 'line1line2', ''))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_err(self, m_parse_frame):
        cur = 0

        def parse_frame(buf):
            nonlocal cur
            yield
            if cur == 0:
                cur = 1
                return (0, websocket.OPCODE_TEXT, b'line1')
            else:
                return (1, websocket.OPCODE_TEXT, b'line2')

        m_parse_frame.side_effect = parse_frame
        buf = aiohttp.ParserBuffer()
        p = websocket.parse_message(buf)
        next(p)
        p.send(b'')
        self.assertRaises(websocket.WebSocketError, p.send, b'')

    @unittest.mock.patch('aiohttp.websocket.parse_message')
    def test_parser(self, m_parse_message):
        cur = 0

        def parse_message(buf):
            nonlocal cur
            yield
            if cur == 0:
                cur = 1
                return websocket.Message(websocket.OPCODE_TEXT, b'line1', b'')
            else:
                return websocket.Message(websocket.OPCODE_CLOSE, b'', b'')

        m_parse_message.side_effect = parse_message
        out = aiohttp.FlowControlDataQueue(unittest.mock.Mock())
        buf = aiohttp.ParserBuffer()
        p = websocket.WebSocketParser(out, buf)
        next(p)
        p.send(b'')
        self.assertRaises(StopIteration, p.send, b'')

        self.assertEqual(
            (websocket.OPCODE_TEXT, b'line1', b''), out._buffer[0])
        self.assertEqual(
            (websocket.OPCODE_CLOSE, b'', b''), out._buffer[1])
        self.assertTrue(out._eof)

    def test_parser_eof(self):
        out = aiohttp.FlowControlDataQueue(unittest.mock.Mock())
        buf = aiohttp.ParserBuffer()
        p = websocket.WebSocketParser(out, buf)
        next(p)
        self.assertRaises(aiohttp.EofStream, p.throw, aiohttp.EofStream)
        self.assertEqual([], list(out._buffer))


class WebsocketWriterTests(unittest.TestCase):

    def setUp(self):
        self.transport = unittest.mock.Mock()
        self.writer = websocket.WebSocketWriter(self.transport, use_mask=False)

    def test_pong(self):
        self.writer.pong()
        self.transport.write.assert_called_with(b'\x8a\x00')

    def test_ping(self):
        self.writer.ping()
        self.transport.write.assert_called_with(b'\x89\x00')

    def test_send_text(self):
        self.writer.send(b'text')
        self.transport.write.assert_called_with(b'\x81\x04text')

    def test_send_binary(self):
        self.writer.send('binary', True)
        self.transport.write.assert_called_with(b'\x82\x06binary')

    def test_send_binary_long(self):
        self.writer.send(b'b' * 127, True)
        self.assertTrue(
            self.transport.write.call_args[0][0].startswith(b'\x82~\x00\x7fb'))

    def test_send_binary_very_long(self):
        self.writer.send(b'b' * 65537, True)
        self.assertTrue(
            self.transport.write.call_args[0][0].startswith(
                b'\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01b'))

    def test_close(self):
        self.writer.close(1001, 'msg')
        self.transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

        self.writer.close(1001, b'msg')
        self.transport.write.assert_called_with(b'\x88\x05\x03\xe9msg')

    def test_send_text_masked(self):
        writer = websocket.WebSocketWriter(self.transport,
                                           use_mask=True,
                                           random=random.Random(123))
        writer.send(b'text')
        self.transport.write.assert_called_with(
            b'\x81\x84\rg\xb3fy\x02\xcb\x12')


class WebSocketHandshakeTests(unittest.TestCase):

    def setUp(self):
        self.transport = unittest.mock.Mock()
        self.headers = multidict.MultiDict()
        self.message = protocol.RawRequestMessage(
            'GET', '/path', (1, 0), self.headers, True, None)

    def test_not_get(self):
        self.assertRaises(
            errors.HttpProcessingError,
            websocket.do_handshake,
            'POST', self.message.headers, self.transport)

    def test_no_upgrade(self):
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

    def test_no_connection(self):
        self.headers.extend([('UPGRADE', 'websocket'),
                             ('CONNECTION', 'keep-alive')])
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

    def test_protocol_version(self):
        self.headers.extend([('UPGRADE', 'websocket'),
                             ('CONNECTION', 'upgrade')])
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

        self.headers.extend([('UPGRADE', 'websocket'),
                             ('CONNECTION', 'upgrade'),
                             ('SEC-WEBSOCKET-VERSION', '1')])
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

    def test_protocol_key(self):
        self.headers.extend([('UPGRADE', 'websocket'),
                             ('CONNECTION', 'upgrade'),
                             ('SEC-WEBSOCKET-VERSION', '13')])
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

        self.headers.extend([('UPGRADE', 'websocket'),
                             ('CONNECTION', 'upgrade'),
                             ('SEC-WEBSOCKET-VERSION', '13'),
                             ('SEC-WEBSOCKET-KEY', '123')])
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

        sec_key = base64.b64encode(os.urandom(2))
        self.headers.extend([('UPGRADE', 'websocket'),
                             ('CONNECTION', 'upgrade'),
                             ('SEC-WEBSOCKET-VERSION', '13'),
                             ('SEC-WEBSOCKET-KEY', sec_key.decode())])
        self.assertRaises(
            errors.HttpBadRequest,
            websocket.do_handshake,
            self.message.method, self.message.headers, self.transport)

    def gen_ws_headers(self, protocols=''):
        key = base64.b64encode(os.urandom(16)).decode()
        hdrs = [('UPGRADE', 'websocket'),
                ('CONNECTION', 'upgrade'),
                ('SEC-WEBSOCKET-VERSION', '13'),
                ('SEC-WEBSOCKET-KEY', key)]
        if protocols:
            hdrs += [('SEC-WEBSOCKET-PROTOCOL', protocols)]
        return hdrs, key

    def test_handshake(self):
        hdrs, sec_key = self.gen_ws_headers()

        self.headers.extend(hdrs)
        status, headers, parser, writer, protocol = websocket.do_handshake(
            self.message.method, self.message.headers, self.transport)
        self.assertEqual(status, 101)
        self.assertIsNone(protocol)

        key = base64.b64encode(
            hashlib.sha1(sec_key.encode() + websocket.WS_KEY).digest())
        headers = dict(headers)
        self.assertEqual(headers['SEC-WEBSOCKET-ACCEPT'], key.decode())

    def test_handshake_protocol(self):
        '''Tests if one protocol is returned by do_handshake'''
        proto = 'chat'

        self.headers.extend(self.gen_ws_headers(proto)[0])
        _, resp_headers, _, _, protocol = websocket.do_handshake(
            self.message.method, self.message.headers, self.transport,
            protocols=[proto])

        self.assertEqual(protocol, proto)

        # also test if we reply with the protocol
        resp_headers = dict(resp_headers)
        self.assertEqual(resp_headers['SEC-WEBSOCKET-PROTOCOL'], proto)

    def test_handshake_protocol_agreement(self):
        '''Tests if the right protocol is selected given multiple'''
        best_proto = 'worse_proto'
        wanted_protos = ['best', 'chat', 'worse_proto']
        server_protos = 'worse_proto,chat'

        self.headers.extend(self.gen_ws_headers(server_protos)[0])
        _, resp_headers, _, _, protocol = websocket.do_handshake(
            self.message.method, self.message.headers, self.transport,
            protocols=wanted_protos)

        self.assertEqual(protocol, best_proto)

    @unittest.mock.patch('aiohttp.websocket.ws_logger.warning')
    def test_handshake_protocol_unsupported(self, m_websocket_warn):
        '''Tests if a protocol mismatch handshake warns and returns None'''
        warn_called = False

        def websocket_warn(msg, *fmts):
            nonlocal warn_called
            warn_called = True
        m_websocket_warn.side_effect = websocket_warn

        proto = 'chat'
        self.headers.extend(self.gen_ws_headers('test')[0])

        _, _, _, _, protocol = websocket.do_handshake(
            self.message.method, self.message.headers, self.transport,
            protocols=[proto])

        self.assertTrue(warn_called, 'protocol mismatch didn’t warn')
        self.assertIsNone(protocol)
