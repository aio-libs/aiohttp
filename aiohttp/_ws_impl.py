"""WebSocket protocol versions 13 and 8."""

import base64
import binascii
import collections
import hashlib
import json
import os
import random
import sys
from enum import IntEnum
from struct import Struct

from aiohttp import errors, hdrs
from aiohttp.helpers import noop
from aiohttp.log import ws_logger

__all__ = ('WebSocketParser', 'WebSocketWriter', 'do_handshake',
           'WSMessage', 'WebSocketError', 'WSMsgType', 'WSCloseCode')


class WSCloseCode(IntEnum):
    OK = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    INVALID_TEXT = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013


ALLOWED_CLOSE_CODES = {int(i) for i in WSCloseCode}


class WSMsgType(IntEnum):
    # websocket spec types
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    PING = 0x9
    PONG = 0xa
    CLOSE = 0x8

    # aiohttp specific types
    CLOSING = 0x100
    CLOSED = 0x101
    ERROR = 0x102

    text = TEXT
    binary = BINARY
    ping = PING
    pong = PONG
    close = CLOSE
    closing = CLOSING
    closed = CLOSED
    error = ERROR


WS_KEY = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


UNPACK_LEN2 = Struct('!H').unpack_from
UNPACK_LEN3 = Struct('!Q').unpack_from
UNPACK_CLOSE_CODE = Struct('!H').unpack
PACK_LEN1 = Struct('!BB').pack
PACK_LEN2 = Struct('!BBH').pack
PACK_LEN3 = Struct('!BBQ').pack
PACK_CLOSE_CODE = Struct('!H').pack
MSG_SIZE = 2 ** 14
DEFAULT_LIMIT = 2 ** 16


_WSMessageBase = collections.namedtuple('_WSMessageBase',
                                        ['type', 'data', 'extra'])


class WSMessage(_WSMessageBase):
    def json(self, *, loads=json.loads):
        """Return parsed JSON data.

        .. versionadded:: 0.22
        """
        return loads(self.data)

    @property
    def tp(self):
        return self.type


CLOSED_MESSAGE = WSMessage(WSMsgType.CLOSED, None, None)
CLOSING_MESSAGE = WSMessage(WSMsgType.CLOSING, None, None)


class WebSocketError(Exception):
    """WebSocket protocol parser error."""

    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def WebSocketParser(out, buf):
    while True:
        fin, opcode, payload = yield from parse_frame(buf)

        if opcode == WSMsgType.CLOSE:
            if len(payload) >= 2:
                close_code = UNPACK_CLOSE_CODE(payload[:2])[0]
                if close_code < 3000 and close_code not in ALLOWED_CLOSE_CODES:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        'Invalid close code: {}'.format(close_code))
                try:
                    close_message = payload[2:].decode('utf-8')
                except UnicodeDecodeError as exc:
                    raise WebSocketError(
                        WSCloseCode.INVALID_TEXT,
                        'Invalid UTF-8 text message') from exc
                msg = WSMessage(WSMsgType.CLOSE, close_code, close_message)
            elif payload:
                raise WebSocketError(
                    WSCloseCode.PROTOCOL_ERROR,
                    'Invalid close frame: {} {} {!r}'.format(
                        fin, opcode, payload))
            else:
                msg = WSMessage(WSMsgType.CLOSE, 0, '')

            out.feed_data(msg, 0)

        elif opcode == WSMsgType.PING:
            out.feed_data(WSMessage(WSMsgType.PING, payload, ''), len(payload))

        elif opcode == WSMsgType.PONG:
            out.feed_data(WSMessage(WSMsgType.PONG, payload, ''), len(payload))

        elif opcode not in (WSMsgType.TEXT, WSMsgType.BINARY):
            raise WebSocketError(
                WSCloseCode.PROTOCOL_ERROR,
                "Unexpected opcode={!r}".format(opcode))
        else:
            # load text/binary
            data = [payload]

            while not fin:
                fin, _opcode, payload = yield from parse_frame(buf, True)

                # We can receive ping/close in the middle of
                # text message, Case 5.*
                if _opcode == WSMsgType.PING:
                    out.feed_data(
                        WSMessage(WSMsgType.PING, payload, ''), len(payload))
                    fin, _opcode, payload = yield from parse_frame(buf, True)
                elif _opcode == WSMsgType.CLOSE:
                    if len(payload) >= 2:
                        close_code = UNPACK_CLOSE_CODE(payload[:2])[0]
                        if (close_code not in ALLOWED_CLOSE_CODES and
                                close_code < 3000):
                            raise WebSocketError(
                                WSCloseCode.PROTOCOL_ERROR,
                                'Invalid close code: {}'.format(close_code))
                        try:
                            close_message = payload[2:].decode('utf-8')
                        except UnicodeDecodeError as exc:
                            raise WebSocketError(
                                WSCloseCode.INVALID_TEXT,
                                'Invalid UTF-8 text message') from exc
                        msg = WSMessage(WSMsgType.CLOSE, close_code,
                                        close_message)
                    elif payload:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            'Invalid close frame: {} {} {!r}'.format(
                                fin, opcode, payload))
                    else:
                        msg = WSMessage(WSMsgType.CLOSE, 0, '')

                    out.feed_data(msg, 0)
                    fin, _opcode, payload = yield from parse_frame(buf, True)

                if _opcode != WSMsgType.CONTINUATION:
                    raise WebSocketError(
                        WSCloseCode.PROTOCOL_ERROR,
                        'The opcode in non-fin frame is expected '
                        'to be zero, got {!r}'.format(_opcode))
                else:
                    data.append(payload)

            if opcode == WSMsgType.TEXT:
                try:
                    text = b''.join(data).decode('utf-8')
                    out.feed_data(WSMessage(WSMsgType.TEXT, text, ''),
                                  len(text))
                except UnicodeDecodeError as exc:
                    raise WebSocketError(
                        WSCloseCode.INVALID_TEXT,
                        'Invalid UTF-8 text message') from exc
            else:
                data = b''.join(data)
                out.feed_data(
                    WSMessage(WSMsgType.BINARY, data, ''), len(data))


native_byteorder = sys.byteorder


def _websocket_mask_python(mask, data):
    """Websocket masking function.

    `mask` is a `bytes` object of length 4; `data` is a `bytes` object
    of any length.  Returns a `bytes` object of the same length as
    `data` with the mask applied as specified in section 5.3 of RFC
    6455.

    This pure-python implementation may be replaced by an optimized
    version when available.

    """
    assert isinstance(data, bytearray), data
    assert len(mask) == 4, mask
    datalen = len(data)
    if datalen == 0:
        # everything work without this, but may be changed later in Python.
        return bytearray()
    data = int.from_bytes(data, native_byteorder)
    mask = int.from_bytes(mask * (datalen // 4) + mask[: datalen % 4],
                          native_byteorder)
    return (data ^ mask).to_bytes(datalen, native_byteorder)


if bool(os.environ.get('AIOHTTP_NO_EXTENSIONS')):
    _websocket_mask = _websocket_mask_python
else:
    try:
        from ._websocket import _websocket_mask_cython
        _websocket_mask = _websocket_mask_cython
    except ImportError:  # pragma: no cover
        _websocket_mask = _websocket_mask_python


def parse_frame(buf, continuation=False):
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
        raise WebSocketError(
            WSCloseCode.PROTOCOL_ERROR,
            'Received frame with non-zero reserved bits')

    if opcode > 0x7 and fin == 0:
        raise WebSocketError(
            WSCloseCode.PROTOCOL_ERROR,
            'Received fragmented control frame')

    if fin == 0 and opcode == WSMsgType.CONTINUATION and not continuation:
        raise WebSocketError(
            WSCloseCode.PROTOCOL_ERROR,
            'Received new fragment frame with non-zero '
            'opcode {!r}'.format(opcode))

    has_mask = (second_byte >> 7) & 1
    length = (second_byte) & 0x7f

    # Control frames MUST have a payload length of 125 bytes or less
    if opcode > 0x7 and length > 125:
        raise WebSocketError(
            WSCloseCode.PROTOCOL_ERROR,
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
        payload = bytearray()

    if has_mask:
        payload = _websocket_mask(bytes(mask), payload)

    return fin, opcode, payload


class WebSocketWriter:

    def __init__(self, writer, *,
                 use_mask=False, limit=DEFAULT_LIMIT, random=random.Random()):
        self.writer = writer
        self.use_mask = use_mask
        self.randrange = random.randrange
        self._closing = False
        self._limit = limit
        self._output_size = 0

    def _send_frame(self, message, opcode):
        """Send a frame over the websocket with message as its payload."""
        if self._closing:
            ws_logger.warning('websocket connection is closing.')

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
            message = _websocket_mask(mask, bytearray(message))
            self.writer.write(header + mask + message)
            self._output_size += len(header) + len(mask) + len(message)
        else:
            if len(message) > MSG_SIZE:
                self.writer.write(header)
                self.writer.write(message)
            else:
                self.writer.write(header + message)

            self._output_size += len(header) + len(message)

        if self._output_size > self._limit:
            self._output_size = 0
            return self.writer.drain()

        return noop()

    def pong(self, message=b''):
        """Send pong message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return self._send_frame(message, WSMsgType.PONG)

    def ping(self, message=b''):
        """Send ping message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return self._send_frame(message, WSMsgType.PING)

    def send(self, message, binary=False):
        """Send a frame over the websocket with message as its payload."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        if binary:
            return self._send_frame(message, WSMsgType.BINARY)
        else:
            return self._send_frame(message, WSMsgType.TEXT)

    def close(self, code=1000, message=b''):
        """Close the websocket, sending the specified code and message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        try:
            return self._send_frame(
                PACK_CLOSE_CODE(code) + message, opcode=WSMsgType.CLOSE)
        finally:
            self._closing = True


def do_handshake(method, headers, transport,
                 protocols=(), write_buffer_size=DEFAULT_LIMIT):
    """Prepare WebSocket handshake.

    It return HTTP response code, response headers, websocket parser,
    websocket writer. It does not perform any IO.

    `protocols` is a sequence of known protocols. On successful handshake,
    the returned response headers contain the first protocol in this list
    which the server also knows.

    `write_buffer_size` max size of write buffer before `drain()` get called.
    """
    # WebSocket accepts only GET
    if method.upper() != hdrs.METH_GET:
        raise errors.HttpProcessingError(
            code=405, headers=((hdrs.ALLOW, hdrs.METH_GET),))

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
                req_protocols, protocols)

    # check supported version
    version = headers.get(hdrs.SEC_WEBSOCKET_VERSION, '')
    if version not in ('13', '8', '7'):
        raise errors.HttpBadRequest(
            message='Unsupported version: {}'.format(version),
            headers=((hdrs.SEC_WEBSOCKET_VERSION, '13'),))

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
            WebSocketWriter(transport, limit=write_buffer_size),
            protocol)
