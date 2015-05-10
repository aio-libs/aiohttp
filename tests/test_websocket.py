"""Tests for http/websocket.py"""

import asyncio
import base64
import hashlib
import os
import random
import struct
import unittest
import unittest.mock

import aiohttp
from aiohttp import websocket, multidict, protocol, errors
from aiohttp.websocket import Message


class TestWebsocketParser(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        self.buf = aiohttp.ParserBuffer()
        self.out = aiohttp.DataQueue(loop=self.loop)

    def tearDown(self):
        self.loop.close()

    def build_frame(self, message, opcode, use_mask=False, noheader=False):
        """Send a frame over the websocket with message as its payload."""
        msg_length = len(message)
        if use_mask:  # pragma: no cover
            mask_bit = 0x80
        else:
            mask_bit = 0

        if msg_length < 126:
            header = websocket.PACK_LEN1(
                0x80 | opcode, msg_length | mask_bit)
        elif msg_length < (1 << 16):  # pragma: no cover
            header = websocket.PACK_LEN2(
                0x80 | opcode, 126 | mask_bit, msg_length)
        else:
            header = websocket.PACK_LEN3(
                0x80 | opcode, 127 | mask_bit, msg_length)

        if use_mask:  # pragma: no cover
            mask = random.randrange(0, 0xffffffff)
            mask = mask.to_bytes(4, 'big')
            message = websocket._websocket_mask(mask, bytearray(message))
            if noheader:
                return message
            else:
                return header + mask + message
        else:
            if noheader:
                return message
            else:
                return header + message

    def build_close_frame(self, code=1000, message=b'', noheader=False):
        """Close the websocket, sending the specified code and message."""
        if isinstance(message, str):  # pragma: no cover
            message = message.encode('utf-8')
        return self.build_frame(
            websocket.PACK_CLOSE_CODE(code) + message,
            opcode=websocket.OPCODE_CLOSE, noheader=noheader)

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
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(res, ((websocket.OPCODE_PING, b'data', ''), 4))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_pong_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_PONG, b'data')
        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(res, ((websocket.OPCODE_PONG, b'data', ''), 4))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_close_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CLOSE, b'')
        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(res, ((websocket.OPCODE_CLOSE, 0, ''), 0))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_close_frame_info(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CLOSE, b'0112345')
        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(
            res, (Message(websocket.OPCODE_CLOSE, 12337, '12345'), 0))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_close_frame_invalid(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CLOSE, b'1')
        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        with self.assertRaises(websocket.WebSocketError) as ctx:
            next(p)

        self.assertEqual(ctx.exception.code, websocket.CLOSE_PROTOCOL_ERROR)

    def test_close_frame_invalid_2(self):
        self.buf.extend(self.build_close_frame(code=1))
        p = websocket.WebSocketParser(self.out, self.buf)
        with self.assertRaises(websocket.WebSocketError) as ctx:
            next(p)

        self.assertEqual(ctx.exception.code, websocket.CLOSE_PROTOCOL_ERROR)

    def test_close_frame_unicode_err(self):
        self.buf.extend(self.build_close_frame(
            code=1000, message=b'\xf4\x90\x80\x80'))
        p = websocket.WebSocketParser(self.out, self.buf)
        with self.assertRaises(websocket.WebSocketError) as ctx:
            next(p)

        self.assertEqual(ctx.exception.code, websocket.CLOSE_INVALID_TEXT)

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_unknown_frame(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_CONTINUATION, b'')
        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        self.assertRaises(websocket.WebSocketError, p.send, b'')

    def test_simple_text(self):
        self.buf.extend(self.build_frame(b'text', websocket.OPCODE_TEXT))
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(res, ((websocket.OPCODE_TEXT, 'text', ''), 4))

    def test_simple_text_unicode_err(self):
        self.buf.extend(
            self.build_frame(b'\xf4\x90\x80\x80', websocket.OPCODE_TEXT))
        p = websocket.WebSocketParser(self.out, self.buf)
        with self.assertRaises(websocket.WebSocketError) as ctx:
            next(p)

        self.assertEqual(ctx.exception.code, websocket.CLOSE_INVALID_TEXT)

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_simple_binary(self, m_parse_frame):
        def parse_frame(buf):
            yield
            return (1, websocket.OPCODE_BINARY, b'binary')
        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(res, ((websocket.OPCODE_BINARY, b'binary', ''), 6))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation(self, m_parse_frame):
        cur = 0

        def parse_frame(buf, cont=False):
            nonlocal cur
            yield
            if cur == 0:
                cur = 1
                return (0, websocket.OPCODE_TEXT, b'line1')
            else:
                return (1, websocket.OPCODE_CONTINUATION, b'line2')

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(
            res, (Message(websocket.OPCODE_TEXT, 'line1line2', ''), 10))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_with_ping(self, m_parse_frame):
        frames = [
            (0, websocket.OPCODE_TEXT, b'line1'),
            (0, websocket.OPCODE_PING, b''),
            (1, websocket.OPCODE_CONTINUATION, b'line2'),
        ]

        def parse_frame(buf, cont=False):
            yield
            return frames.pop(0)

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        p.send(b'')
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(
            res, (Message(websocket.OPCODE_PING, b'', ''), 0))
        res = self.out._buffer[1]
        self.assertEqual(
            res, (Message(websocket.OPCODE_TEXT, 'line1line2', ''), 10))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_err(self, m_parse_frame):
        cur = 0

        def parse_frame(buf, cont=False):
            nonlocal cur
            yield
            if cur == 0:
                cur = 1
                return (0, websocket.OPCODE_TEXT, b'line1')
            else:
                return (1, websocket.OPCODE_TEXT, b'line2')

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        self.assertRaises(websocket.WebSocketError, p.send, b'')

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_with_close(self, m_parse_frame):
        frames = [
            (0, websocket.OPCODE_TEXT, b'line1'),
            (0, websocket.OPCODE_CLOSE,
             self.build_close_frame(1002, b'test', noheader=True)),
            (1, websocket.OPCODE_CONTINUATION, b'line2'),
        ]

        def parse_frame(buf, cont=False):
            yield
            return frames.pop(0)

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        p.send(b'')
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(
            res, (Message(websocket.OPCODE_CLOSE, 1002, 'test'), 0))
        res = self.out._buffer[1]
        self.assertEqual(
            res, (Message(websocket.OPCODE_TEXT, 'line1line2', ''), 10))

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_with_close_unicode_err(self, m_parse_frame):
        frames = [
            (0, websocket.OPCODE_TEXT, b'line1'),
            (0, websocket.OPCODE_CLOSE,
             self.build_close_frame(1000, b'\xf4\x90\x80\x80', noheader=True)),
            (1, websocket.OPCODE_CONTINUATION, b'line2')]

        def parse_frame(buf, cont=False):
            yield
            return frames.pop(0)

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        with self.assertRaises(websocket.WebSocketError) as ctx:
            p.send(b'')

        self.assertEqual(ctx.exception.code, websocket.CLOSE_INVALID_TEXT)

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_with_close_bad_code(self, m_parse_frame):
        frames = [
            (0, websocket.OPCODE_TEXT, b'line1'),
            (0, websocket.OPCODE_CLOSE,
             self.build_close_frame(1, b'test', noheader=True)),
            (1, websocket.OPCODE_CONTINUATION, b'line2')]

        def parse_frame(buf, cont=False):
            yield
            return frames.pop(0)

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        with self.assertRaises(websocket.WebSocketError) as ctx:
            p.send(b'')

        self.assertEqual(ctx.exception.code, websocket.CLOSE_PROTOCOL_ERROR)

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_with_close_bad_payload(self, m_parse_frame):
        frames = [
            (0, websocket.OPCODE_TEXT, b'line1'),
            (0, websocket.OPCODE_CLOSE, b'1'),
            (1, websocket.OPCODE_CONTINUATION, b'line2')]

        def parse_frame(buf, cont=False):
            yield
            return frames.pop(0)

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        with self.assertRaises(websocket.WebSocketError) as ctx:
            p.send(b'')

        self.assertEqual(ctx.exception.code, websocket.CLOSE_PROTOCOL_ERROR)

    @unittest.mock.patch('aiohttp.websocket.parse_frame')
    def test_continuation_with_close_empty(self, m_parse_frame):
        frames = [
            (0, websocket.OPCODE_TEXT, b'line1'),
            (0, websocket.OPCODE_CLOSE, b''),
            (1, websocket.OPCODE_CONTINUATION, b'line2'),
        ]

        def parse_frame(buf, cont=False):
            yield
            return frames.pop(0)

        m_parse_frame.side_effect = parse_frame
        p = websocket.WebSocketParser(self.out, self.buf)
        next(p)
        p.send(b'')
        p.send(b'')
        p.send(b'')
        res = self.out._buffer[0]
        self.assertEqual(
            res, (Message(websocket.OPCODE_CLOSE, 0, ''), 0))
        res = self.out._buffer[1]
        self.assertEqual(
            res, (Message(websocket.OPCODE_TEXT, 'line1line2', ''), 10))


class TestWebsocketWriter(unittest.TestCase):

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
        self.assertEqual(
            self.transport.write.call_args_list[0][0][0],
            b'\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x01')
        self.assertEqual(
            self.transport.write.call_args_list[1][0][0],
            b'b' * 65537)

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


class TestWebSocketHandshake(unittest.TestCase):

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
