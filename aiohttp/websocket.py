"""WebSocket protocol versions 13 and 8."""

import base64
import binascii
import collections
import hashlib
import os
import random

from struct import Struct
from aiohttp import errors, hdrs
from aiohttp.log import ws_logger

__all__ = ('WebSocketParser', 'WebSocketWriter', 'do_handshake',
           'Message', 'WebSocketError',
           'MSG_TEXT', 'MSG_BINARY', 'MSG_CLOSE', 'MSG_PING', 'MSG_PONG')

# Frame opcodes defined in the spec.
OPCODE_CONTINUATION = 0x0
MSG_TEXT = OPCODE_TEXT = 0x1
MSG_BINARY = OPCODE_BINARY = 0x2
MSG_CLOSE = OPCODE_CLOSE = 0x8
MSG_PING = OPCODE_PING = 0x9
MSG_PONG = OPCODE_PONG = 0xa

WS_KEY = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
WS_HDRS = (hdrs.UPGRADE,
           hdrs.CONNECTION,
           hdrs.SEC_WEBSOCKET_VERSION,
           hdrs.SEC_WEBSOCKET_KEY,
           hdrs.SEC_WEBSOCKET_PROTOCOL)

Message = collections.namedtuple('Message', ['tp', 'data', 'extra'])

UNPACK_LEN2 = Struct('!H').unpack_from
UNPACK_LEN3 = Struct('!Q').unpack_from
UNPACK_CLOSE_CODE = Struct('!H').unpack
PACK_LEN1 = Struct('!BB').pack
PACK_LEN2 = Struct('!BBH').pack
PACK_LEN3 = Struct('!BBQ').pack
PACK_CLOSE_CODE = Struct('!H').pack


class WebSocketError(Exception):
    """WebSocket protocol parser error."""


def WebSocketParser(out, buf):
    while True:
        message = yield from parse_message(buf)
        out.feed_data(message)

        if message.tp == MSG_CLOSE:
            out.feed_eof()
            break


def _websocket_mask_python(mask, data):
    """Websocket masking function.

    `mask` is a `bytes` object of length 4; `data` is a `bytes` object
    of any length.  Returns a `bytes` object of the same length as
    `data` with the mask applied as specified in section 5.3 of RFC
    6455.

    This pure-python implementation may be replaced by an optimized
    version when available.

    """
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data))


if bool(os.environ.get('AIOHTTP_NO_EXTENSIONS')):
    _websocket_mask = _websocket_mask_python
else:
    try:
        from ._websocket import _websocket_mask_cython
        _websocket_mask = _websocket_mask_cython
    except ImportError:  # pragma: no cover
        _websocket_mask = _websocket_mask_python


def parse_frame(buf):
    """Return the next frame from the socket."""
    # read header
    data = yield from buf.read(2)
    first_byte, second_byte = data

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
        length = UNPACK_LEN2(data)[0]
    elif length > 126:
        data = yield from buf.read(8)
        length = UNPACK_LEN3(data)[0]

    if has_mask:
        mask = yield from buf.read(4)

    if length:
        payload = yield from buf.read(length)
    else:
        payload = b''

    if has_mask:
        payload = _websocket_mask(mask, payload)

    return fin, opcode, payload


def parse_message(buf):
    fin, opcode, payload = yield from parse_frame(buf)

    if opcode == OPCODE_CLOSE:
        if len(payload) >= 2:
            close_code = UNPACK_CLOSE_CODE(payload[:2])[0]
            close_message = payload[2:]
            return Message(OPCODE_CLOSE, close_code, close_message)
        elif payload:
            raise WebSocketError(
                'Invalid close frame: {} {} {!r}'.format(fin, opcode, payload))
        return Message(OPCODE_CLOSE, 0, '')

    elif opcode == OPCODE_PING:
        return Message(OPCODE_PING, payload, '')

    elif opcode == OPCODE_PONG:
        return Message(OPCODE_PONG, payload, '')

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

    def __init__(self, writer, *, use_mask=False, random=random.Random()):
        self.writer = writer
        self.use_mask = use_mask
        self.randrange = random.randrange

    def _send_frame(self, message, opcode):
        """Send a frame over the websocket with message as its payload."""
        msg_length = len(message)

        use_mask = self.use_mask
        if use_mask:
            mask_bit = 0x80
        else:
            mask_bit = 0

        if msg_length < 126:
            header = PACK_LEN1(0x80 | opcode, msg_length | mask_bit)
        elif msg_length < (1 << 16):
            header = PACK_LEN2(0x80 | opcode, 126 | mask_bit, msg_length)
        else:
            header = PACK_LEN3(0x80 | opcode, 127 | mask_bit, msg_length)
        if use_mask:
            mask = self.randrange(0, 0xffffffff)
            mask = mask.to_bytes(4, 'big')
            message = _websocket_mask(mask, message)
            self.writer.write(header + mask + message)
        else:
            self.writer.write(header + message)

    def pong(self, message=b''):
        """Send pong message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        self._send_frame(message, OPCODE_PONG)

    def ping(self, message=b''):
        """Send ping message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        self._send_frame(message, OPCODE_PING)

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
            PACK_CLOSE_CODE(code) + message,
            opcode=OPCODE_CLOSE)


def do_handshake(method, headers, transport, protocols=()):
    """Prepare WebSocket handshake.

    It return http response code, response headers, websocket parser,
    websocket writer. It does not perform any IO.

    `protocols` is a sequence of known protocols. On successful handshake,
    the returned response headers contain the first protocol in this list
    which the server also knows.

    """
    # WebSocket accepts only GET
    if method.upper() != 'GET':
        raise errors.HttpProcessingError(code=405, headers=(('Allow', 'GET'),))

    if 'websocket' != headers.get(hdrs.UPGRADE, '').lower().strip():
        raise errors.HttpBadRequest(
            message='No WebSocket UPGRADE hdr: {}\n Can '
            '"Upgrade" only to "WebSocket".'.format(headers.get(hdrs.UPGRADE)))

    if 'upgrade' not in headers.get(hdrs.CONNECTION, '').lower():
        raise errors.HttpBadRequest(
            message='No CONNECTION upgrade hdr: {}'.format(
                headers.get(hdrs.CONNECTION)))

    # find common sub-protocol between client and server
    protocol = None
    if hdrs.SEC_WEBSOCKET_PROTOCOL in headers:
        req_protocols = [str(proto.strip()) for proto in
                         headers[hdrs.SEC_WEBSOCKET_PROTOCOL].split(',')]

        for proto in req_protocols:
            if proto in protocols:
                protocol = proto
                break
        else:
            # No overlap found: Return no protocol as per spec
            ws_logger.warning(
                'Client protocols %r don’t overlap server-known ones %r',
                protocols, req_protocols)

    # check supported version
    version = headers.get(hdrs.SEC_WEBSOCKET_VERSION)
    if version not in ('13', '8', '7'):
        raise errors.HttpBadRequest(
            message='Unsupported version: {}'.format(version),
            headers=(('Sec-WebSocket-Version', '13', '8', '7'),))

    # check client handshake for validity
    key = headers.get(hdrs.SEC_WEBSOCKET_KEY)
    try:
        if not key or len(base64.b64decode(key)) != 16:
            raise errors.HttpBadRequest(
                message='Handshake error: {!r}'.format(key))
    except binascii.Error:
        raise errors.HttpBadRequest(
            message='Handshake error: {!r}'.format(key)) from None

    response_headers = [
        (hdrs.UPGRADE, 'websocket'),
        (hdrs.CONNECTION, 'upgrade'),
        (hdrs.TRANSFER_ENCODING, 'chunked'),
        (hdrs.SEC_WEBSOCKET_ACCEPT, base64.b64encode(
            hashlib.sha1(key.encode() + WS_KEY).digest()).decode())]

    if protocol:
        response_headers.append((hdrs.SEC_WEBSOCKET_PROTOCOL, protocol))

    # response code, headers, parser, writer, protocol
    return (101,
            response_headers,
            WebSocketParser,
            WebSocketWriter(transport),
            protocol)
