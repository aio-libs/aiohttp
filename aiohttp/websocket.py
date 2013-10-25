"""WebSocket protocol versions 13 and 8."""

__all__ = ['WebSocketParser', 'WebSocketWriter', 'do_handshake',
           'Message', 'WebSocketError',
           'MSG_TEXT', 'MSG_BINARY', 'MSG_CLOSE', 'MSG_PING', 'MSG_PONG']

import base64
import binascii
import collections
import hashlib
import struct
from aiohttp import errors

# Frame opcodes defined in the spec.
OPCODE_CONTINUATION = 0x0
MSG_TEXT = OPCODE_TEXT = 0x1
MSG_BINARY = OPCODE_BINARY = 0x2
MSG_CLOSE = OPCODE_CLOSE = 0x8
MSG_PING = OPCODE_PING = 0x9
MSG_PONG = OPCODE_PONG = 0xa

WS_KEY = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
WS_HDRS = ('UPGRADE', 'CONNECTION',
           'SEC-WEBSOCKET-VERSION', 'SEC-WEBSOCKET-KEY')

Message = collections.namedtuple('Message', ['tp', 'data', 'extra'])


class WebSocketError(Exception):
    """WebSocket protocol parser error."""


def WebSocketParser(out, buf):
    while True:
        message = yield from parse_message(buf)
        out.feed_data(message)

        if message.tp == MSG_CLOSE:
            out.feed_eof()
            break


def parse_frame(buf):
    """Return the next frame from the socket."""
    # read header
    data = yield from buf.read(2)
    first_byte, second_byte = struct.unpack('!BB', data)

    fin = (first_byte >> 7) & 1
    rsv1 = (first_byte >> 6) & 1
    rsv2 = (first_byte >> 5) & 1
    rsv3 = (first_byte >> 4) & 1
    opcode = first_byte & 0xf

    # frame-fin = %x0 ; more frames of this message follow
    #           / %x1 ; final frame of this message
    # frame-rsv1 = %x0 ; 1 bit, MUST be 0 unless negotiated otherwise
    # frame-rsv2 = %x0 ; 1 bit, MUST be 0 unless negotiated otherwise
    # frame-rsv3 = %x0 ; 1 bit, MUST be 0 unless negotiated otherwise
    if rsv1 or rsv2 or rsv3:
        raise WebSocketError('Received frame with non-zero reserved bits')

    if opcode > 0x7 and fin == 0:
        raise WebSocketError('Received fragmented control frame')

    if fin == 0 and opcode == OPCODE_CONTINUATION:
        raise WebSocketError(
            'Received new fragment frame with non-zero opcode')

    has_mask = (second_byte >> 7) & 1
    length = (second_byte) & 0x7f

    # Control frames MUST have a payload length of 125 bytes or less
    if opcode > 0x7 and length > 125:
        raise WebSocketError(
            "Control frame payload cannot be larger than 125 bytes")

    # read payload
    if length == 126:
        data = yield from buf.read(2)
        length = struct.unpack_from('!H', data)[0]
    elif length > 126:
        data = yield from buf.read(8)
        length = struct.unpack_from('!Q', data)[0]

    if has_mask:
        mask = yield from buf.read(4)

    if length:
        payload = yield from buf.read(length)
    else:
        payload = b''

    if has_mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    return fin, opcode, payload


def parse_message(buf):
    fin, opcode, payload = yield from parse_frame(buf)

    if opcode == OPCODE_CLOSE:
        if len(payload) >= 2:
            close_code = struct.unpack('!H', payload[:2])[0]
            close_message = payload[2:]
            return Message(OPCODE_CLOSE, close_code, close_message)
        elif payload:
            raise WebSocketError(
                'Invalid close frame: {} {} {!r}'.format(fin, opcode, payload))
        return Message(OPCODE_CLOSE, '', '')

    elif opcode == OPCODE_PING:
        return Message(OPCODE_PING, '', '')

    elif opcode == OPCODE_PONG:
        return Message(OPCODE_PONG, '', '')

    elif opcode not in (OPCODE_TEXT, OPCODE_BINARY):
        raise WebSocketError("Unexpected opcode={!r}".format(opcode))

    # load text/binary
    data = [payload]

    while not fin:
        fin, _opcode, payload = yield from parse_frame(buf)
        if _opcode != OPCODE_CONTINUATION:
            raise WebSocketError(
                'The opcode in non-fin frame is expected '
                'to be zero, got {!r}'.format(opcode))
        else:
            data.append(payload)

    if opcode == OPCODE_TEXT:
        return Message(OPCODE_TEXT, b''.join(data).decode('utf-8'), '')
    else:
        return Message(OPCODE_BINARY, b''.join(data), '')


class WebSocketWriter:

    def __init__(self, transport):
        self.transport = transport

    def _send_frame(self, message, opcode):
        """Send a frame over the websocket with message as its payload."""
        header = bytes([0x80 | opcode])
        msg_length = len(message)

        if msg_length < 126:
            header += bytes([msg_length])
        elif msg_length < (1 << 16):
            header += bytes([126]) + struct.pack('!H', msg_length)
        else:
            header += bytes([127]) + struct.pack('!Q', msg_length)

        self.transport.write(header + message)

    def pong(self):
        """Send pong message."""
        self._send_frame(b'', OPCODE_PONG)

    def ping(self):
        """Send pong message."""
        self._send_frame(b'', OPCODE_PING)

    def send(self, message, binary=False):
        """Send a frame over the websocket with message as its payload."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        if binary:
            self._send_frame(message, OPCODE_BINARY)
        else:
            self._send_frame(message, OPCODE_TEXT)

    def close(self, code=1000, message=b''):
        """Close the websocket, sending the specified code and message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        self._send_frame(
            struct.pack('!H%ds' % len(message), code, message),
            opcode=OPCODE_CLOSE)


def do_handshake(method, headers, transport):
    """Prepare WebSocket handshake. It return http response code,
    response headers, websocket parser, websocket writer. It does not
    perform any IO."""

    # WebSocket accepts only GET
    if method.upper() != 'GET':
        raise errors.HttpErrorException(405, headers=(('Allow', 'GET'),))

    headers = dict(((hdr, val) for hdr, val in headers if hdr in WS_HDRS))

    if 'websocket' != headers.get('UPGRADE', '').lower().strip():
        raise errors.BadRequestException(
            'No WebSocket UPGRADE hdr: {}\n'
            'Can "Upgrade" only to "WebSocket".'.format(
                headers.get('UPGRADE')))

    if 'upgrade' not in headers.get('CONNECTION', '').lower():
        raise errors.BadRequestException(
            'No CONNECTION upgrade hdr: {}'.format(
                headers.get('CONNECTION')))

    # check supported version
    version = headers.get('SEC-WEBSOCKET-VERSION')
    if version not in ('13', '8', '7'):
        raise errors.BadRequestException(
            'Unsupported version: {}'.format(version))

    # check client handshake for validity
    key = headers.get('SEC-WEBSOCKET-KEY')
    try:
        if not key or len(base64.b64decode(key)) != 16:
            raise errors.BadRequestException(
                'Handshake error: {!r}'.format(key))
    except binascii.Error:
        raise errors.BadRequestException(
            'Handshake error: {!r}'.format(key)) from None

    # response code, headers, parser, writer
    return (101,
            (('UPGRADE', 'websocket'),
             ('CONNECTION', 'upgrade'),
             ('TRANSFER-ENCODING', 'chunked'),
             ('SEC-WEBSOCKET-ACCEPT', base64.b64encode(
                 hashlib.sha1(key.encode() + WS_KEY).digest()).decode())),
            WebSocketParser,
            WebSocketWriter(transport))
