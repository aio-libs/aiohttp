"""WebSocket protocol versions 13 and 8."""

import base64
import binascii
import collections
import hashlib
import json
import random
import re
import sys
import zlib
from enum import IntEnum
from struct import Struct

from . import hdrs
from .helpers import NO_EXTENSIONS, noop
from .http_exceptions import HttpBadRequest, HttpProcessingError
from .log import ws_logger


__all__ = ('WS_CLOSED_MESSAGE', 'WS_CLOSING_MESSAGE', 'WS_KEY',
           'WebSocketReader', 'WebSocketWriter', 'do_handshake',
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


WS_CLOSED_MESSAGE = WSMessage(WSMsgType.CLOSED, None, None)
WS_CLOSING_MESSAGE = WSMessage(WSMsgType.CLOSING, None, None)


class WebSocketError(Exception):
    """WebSocket protocol parser error."""

    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


class WSHandshakeError(Exception):
    """WebSocket protocol handshake error."""


native_byteorder = sys.byteorder


# Used by _websocket_mask_python
_XOR_TABLE = [bytes(a ^ b for a in range(256)) for b in range(256)]


def _websocket_mask_python(mask, data):
    """Websocket masking function.

    `mask` is a `bytes` object of length 4; `data` is a `bytearray`
    object of any length. The contents of `data` are masked with `mask`,
    as specified in section 5.3 of RFC 6455.

    Note that this function mutates the `data` argument.

    This pure-python implementation may be replaced by an optimized
    version when available.

    """
    assert isinstance(data, bytearray), data
    assert len(mask) == 4, mask

    if data:
        a, b, c, d = (_XOR_TABLE[n] for n in mask)
        data[::4] = data[::4].translate(a)
        data[1::4] = data[1::4].translate(b)
        data[2::4] = data[2::4].translate(c)
        data[3::4] = data[3::4].translate(d)


if NO_EXTENSIONS:
    _websocket_mask = _websocket_mask_python
else:
    try:
        from ._websocket import _websocket_mask_cython
        _websocket_mask = _websocket_mask_cython
    except ImportError:  # pragma: no cover
        _websocket_mask = _websocket_mask_python

_WS_DEFLATE_TRAILING = bytes([0x00, 0x00, 0xff, 0xff])


_WS_EXT_RE = re.compile(r'^(?:;\s*(?:'
                        r'(server_no_context_takeover)|'
                        r'(client_no_context_takeover)|'
                        r'(server_max_window_bits(?:=(\d+))?)|'
                        r'(client_max_window_bits(?:=(\d+))?)))*$')

_WS_EXT_RE_SPLIT = re.compile(r'permessage-deflate([^,]+)?')


def ws_ext_parse(extstr, isserver=False):
    if not extstr:
        return 0, False

    compress = 0
    notakeover = False
    for ext in _WS_EXT_RE_SPLIT.finditer(extstr):
        defext = ext.group(1)
        # Return compress = 15 when get `permessage-deflate`
        if not defext:
            compress = 15
            break
        match = _WS_EXT_RE.match(defext)
        if match:
            compress = 15
            if isserver:
                # Server never fail to detect compress handshake.
                # Server does not need to send max wbit to client
                if match.group(4):
                    compress = int(match.group(4))
                    # Group3 must match if group4 matches
                    # Compress wbit 8 does not support in zlib
                    # If compress level not support,
                    # CONTINUE to next extension
                    if compress > 15 or compress < 9:
                        compress = 0
                        continue
                if match.group(1):
                    notakeover = True
                # Ignore regex group 5 & 6 for client_max_window_bits
                break
            else:
                if match.group(6):
                    compress = int(match.group(6))
                    # Group5 must match if group6 matches
                    # Compress wbit 8 does not support in zlib
                    # If compress level not support,
                    # FAIL the parse progress
                    if compress > 15 or compress < 9:
                        raise WSHandshakeError('Invalid window size')
                if match.group(2):
                    notakeover = True
                # Ignore regex group 5 & 6 for client_max_window_bits
                break
        # Return Fail if client side and not match
        elif not isserver:
            raise WSHandshakeError('Extension for deflate not supported' +
                                   ext.group(1))

    return compress, notakeover


def ws_ext_gen(compress=15, isserver=False,
               server_notakeover=False):
    # client_notakeover=False not used for server
    # compress wbit 8 does not support in zlib
    if compress < 9 or compress > 15:
        raise ValueError('Compress wbits must between 9 and 15, '
                         'zlib does not support wbits=8')
    enabledext = ['permessage-deflate']
    if not isserver:
        enabledext.append('client_max_window_bits')

    if compress < 15:
        enabledext.append('server_max_window_bits=' + str(compress))
    if server_notakeover:
        enabledext.append('server_no_context_takeover')
    # if client_notakeover:
    #     enabledext.append('client_no_context_takeover')
    return '; '.join(enabledext)


class WSParserState(IntEnum):
    READ_HEADER = 1
    READ_PAYLOAD_LENGTH = 2
    READ_PAYLOAD_MASK = 3
    READ_PAYLOAD = 4


class WebSocketReader:

    def __init__(self, queue, compress=True):
        self.queue = queue

        self._exc = None
        self._partial = []
        self._state = WSParserState.READ_HEADER

        self._opcode = None
        self._frame_fin = False
        self._frame_opcode = None
        self._frame_payload = bytearray()

        self._tail = b''
        self._has_mask = False
        self._frame_mask = None
        self._payload_length = 0
        self._payload_length_flag = 0
        self._compressed = None
        self._decompressobj = None
        self._compress = compress

    def feed_eof(self):
        self.queue.feed_eof()

    def feed_data(self, data):
        if self._exc:
            return True, data

        try:
            return self._feed_data(data)
        except Exception as exc:
            self._exc = exc
            self.queue.set_exception(exc)
            return True, b''

    def _feed_data(self, data):
        for fin, opcode, payload, compressed in self.parse_frame(data):
            if compressed and not self._decompressobj:
                self._decompressobj = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
            if opcode == WSMsgType.CLOSE:
                if len(payload) >= 2:
                    close_code = UNPACK_CLOSE_CODE(payload[:2])[0]
                    if (close_code < 3000 and
                            close_code not in ALLOWED_CLOSE_CODES):
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

                self.queue.feed_data(msg, 0)

            elif opcode == WSMsgType.PING:
                self.queue.feed_data(
                    WSMessage(WSMsgType.PING, payload, ''), len(payload))

            elif opcode == WSMsgType.PONG:
                self.queue.feed_data(
                    WSMessage(WSMsgType.PONG, payload, ''), len(payload))

            elif opcode not in (
                    WSMsgType.TEXT, WSMsgType.BINARY) and self._opcode is None:
                raise WebSocketError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Unexpected opcode={!r}".format(opcode))
            else:
                # load text/binary
                if not fin:
                    # got partial frame payload
                    if opcode != WSMsgType.CONTINUATION:
                        self._opcode = opcode
                    self._partial.append(payload)
                else:
                    # previous frame was non finished
                    # we should get continuation opcode
                    if self._partial:
                        if opcode != WSMsgType.CONTINUATION:
                            raise WebSocketError(
                                WSCloseCode.PROTOCOL_ERROR,
                                'The opcode in non-fin frame is expected '
                                'to be zero, got {!r}'.format(opcode))

                    if opcode == WSMsgType.CONTINUATION:
                        opcode = self._opcode
                        self._opcode = None

                    self._partial.append(payload)

                    payload_merged = b''.join(self._partial)

                    # Decompress process must to be done after all packets
                    # received.
                    if compressed:
                        payload_merged = self._decompressobj.decompress(
                            payload_merged + _WS_DEFLATE_TRAILING)

                    self._partial.clear()

                    if opcode == WSMsgType.TEXT:
                        try:
                            text = payload_merged.decode('utf-8')
                            self.queue.feed_data(
                                WSMessage(WSMsgType.TEXT, text, ''), len(text))
                        except UnicodeDecodeError as exc:
                            raise WebSocketError(
                                WSCloseCode.INVALID_TEXT,
                                'Invalid UTF-8 text message') from exc
                    else:
                        self.queue.feed_data(
                            WSMessage(WSMsgType.BINARY, payload_merged, ''),
                            len(payload_merged))

        return False, b''

    def parse_frame(self, buf):
        """Return the next frame from the socket."""
        frames = []
        if self._tail:
            buf, self._tail = self._tail + buf, b''

        start_pos = 0
        buf_length = len(buf)

        while True:
            # read header
            if self._state == WSParserState.READ_HEADER:
                if buf_length - start_pos >= 2:
                    data = buf[start_pos:start_pos+2]
                    start_pos += 2
                    first_byte, second_byte = data

                    fin = (first_byte >> 7) & 1
                    rsv1 = (first_byte >> 6) & 1
                    rsv2 = (first_byte >> 5) & 1
                    rsv3 = (first_byte >> 4) & 1
                    opcode = first_byte & 0xf

                    # frame-fin = %x0 ; more frames of this message follow
                    #           / %x1 ; final frame of this message
                    # frame-rsv1 = %x0 ;
                    #    1 bit, MUST be 0 unless negotiated otherwise
                    # frame-rsv2 = %x0 ;
                    #    1 bit, MUST be 0 unless negotiated otherwise
                    # frame-rsv3 = %x0 ;
                    #    1 bit, MUST be 0 unless negotiated otherwise
                    #
                    # Remove rsv1 from this test for deflate development
                    if rsv2 or rsv3 or (rsv1 and not self._compress):
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            'Received frame with non-zero reserved bits')

                    if opcode > 0x7 and fin == 0:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            'Received fragmented control frame')

                    has_mask = (second_byte >> 7) & 1
                    length = (second_byte) & 0x7f

                    # Control frames MUST have a payload
                    # length of 125 bytes or less
                    if opcode > 0x7 and length > 125:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            'Control frame payload cannot be '
                            'larger than 125 bytes')

                    # Set compress status if last package is FIN
                    # OR set compress status if this is first fragment
                    # Raise error if not first fragment with rsv1 = 0x1
                    if self._frame_fin or self._compressed is None:
                        self._compressed = True if rsv1 else False
                    elif rsv1:
                        raise WebSocketError(
                            WSCloseCode.PROTOCOL_ERROR,
                            'Received frame with non-zero reserved bits')

                    self._frame_fin = fin
                    self._frame_opcode = opcode
                    self._has_mask = has_mask
                    self._payload_length_flag = length
                    self._state = WSParserState.READ_PAYLOAD_LENGTH
                else:
                    break

            # read payload length
            if self._state == WSParserState.READ_PAYLOAD_LENGTH:
                length = self._payload_length_flag
                if length == 126:
                    if buf_length - start_pos >= 2:
                        data = buf[start_pos:start_pos+2]
                        start_pos += 2
                        length = UNPACK_LEN2(data)[0]
                        self._payload_length = length
                        self._state = (
                            WSParserState.READ_PAYLOAD_MASK
                            if self._has_mask
                            else WSParserState.READ_PAYLOAD)
                    else:
                        break
                elif length > 126:
                    if buf_length - start_pos >= 8:
                        data = buf[start_pos:start_pos+8]
                        start_pos += 8
                        length = UNPACK_LEN3(data)[0]
                        self._payload_length = length
                        self._state = (
                            WSParserState.READ_PAYLOAD_MASK
                            if self._has_mask
                            else WSParserState.READ_PAYLOAD)
                    else:
                        break
                else:
                    self._payload_length = length
                    self._state = (
                        WSParserState.READ_PAYLOAD_MASK
                        if self._has_mask
                        else WSParserState.READ_PAYLOAD)

            # read payload mask
            if self._state == WSParserState.READ_PAYLOAD_MASK:
                if buf_length - start_pos >= 4:
                    self._frame_mask = buf[start_pos:start_pos+4]
                    start_pos += 4
                    self._state = WSParserState.READ_PAYLOAD
                else:
                    break

            if self._state == WSParserState.READ_PAYLOAD:
                length = self._payload_length
                payload = self._frame_payload

                chunk_len = buf_length - start_pos
                if length >= chunk_len:
                    self._payload_length = length - chunk_len
                    payload.extend(buf[start_pos:])
                    start_pos = buf_length
                else:
                    self._payload_length = 0
                    payload.extend(buf[start_pos:start_pos+length])
                    start_pos = start_pos + length

                if self._payload_length == 0:
                    if self._has_mask:
                        _websocket_mask(self._frame_mask, payload)

                    frames.append((
                        self._frame_fin,
                        self._frame_opcode,
                        payload,
                        self._compressed))

                    self._frame_payload = bytearray()
                    self._state = WSParserState.READ_HEADER
                else:
                    break

        self._tail = buf[start_pos:]

        return frames


class WebSocketWriter:

    def __init__(self, stream, *,
                 use_mask=False, limit=DEFAULT_LIMIT, random=random.Random(),
                 compress=0, notakeover=False):
        self.stream = stream
        self.writer = stream.transport
        self.use_mask = use_mask
        self.randrange = random.randrange
        self.compress = compress
        self.notakeover = notakeover
        self._closing = False
        self._limit = limit
        self._output_size = 0
        self._compressobj = None

    def _send_frame(self, message, opcode):
        """Send a frame over the websocket with message as its payload."""
        if self._closing:
            ws_logger.warning('websocket connection is closing.')

        rsv = 0

        # Only compress larger packets (disabled)
        # Does small packet needs to be compressed?
        # if self.compress and opcode < 8 and len(message) > 124:
        if self.compress and opcode < 8:
            if not self._compressobj:
                self._compressobj = zlib.compressobj(wbits=-self.compress)

            message = self._compressobj.compress(message)
            message = message + self._compressobj.flush(
                zlib.Z_FULL_FLUSH if self.notakeover else zlib.Z_SYNC_FLUSH)
            if message.endswith(_WS_DEFLATE_TRAILING):
                message = message[:-4]
            rsv = rsv | 0x40

        msg_length = len(message)

        use_mask = self.use_mask
        if use_mask:
            mask_bit = 0x80
        else:
            mask_bit = 0

        if msg_length < 126:
            header = PACK_LEN1(0x80 | rsv | opcode, msg_length | mask_bit)
        elif msg_length < (1 << 16):
            header = PACK_LEN2(0x80 | rsv | opcode, 126 | mask_bit, msg_length)
        else:
            header = PACK_LEN3(0x80 | rsv | opcode, 127 | mask_bit, msg_length)
        if use_mask:
            mask = self.randrange(0, 0xffffffff)
            mask = mask.to_bytes(4, 'big')
            message = bytearray(message)
            _websocket_mask(mask, message)
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
            return self.stream.drain()

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


def do_handshake(method, headers, stream, protocols=(),
                 write_buffer_size=DEFAULT_LIMIT, compress=True):
    """Prepare WebSocket handshake.

    It return HTTP response code, response headers, websocket parser,
    websocket writer. It does not perform any IO.

    `protocols` is a sequence of known protocols. On successful handshake,
    the returned response headers contain the first protocol in this list
    which the server also knows.

    `write_buffer_size` max size of write buffer before `drain()` get called.

    `compress` enable or disable server side deflate extension support.
    """
    # WebSocket accepts only GET
    if method.upper() != hdrs.METH_GET:
        raise HttpProcessingError(
            code=405, headers=((hdrs.ALLOW, hdrs.METH_GET),))

    if 'websocket' != headers.get(hdrs.UPGRADE, '').lower().strip():
        raise HttpBadRequest(
            message='No WebSocket UPGRADE hdr: {}\n Can '
            '"Upgrade" only to "WebSocket".'.format(headers.get(hdrs.UPGRADE)))

    if 'upgrade' not in headers.get(hdrs.CONNECTION, '').lower():
        raise HttpBadRequest(
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
        raise HttpBadRequest(
            message='Unsupported version: {}'.format(version),
            headers=((hdrs.SEC_WEBSOCKET_VERSION, '13'),))

    # check client handshake for validity
    key = headers.get(hdrs.SEC_WEBSOCKET_KEY)
    try:
        if not key or len(base64.b64decode(key)) != 16:
            raise HttpBadRequest(
                message='Handshake error: {!r}'.format(key))
    except binascii.Error:
        raise HttpBadRequest(
            message='Handshake error: {!r}'.format(key)) from None

    response_headers = [
        (hdrs.UPGRADE, 'websocket'),
        (hdrs.CONNECTION, 'upgrade'),
        (hdrs.TRANSFER_ENCODING, 'chunked'),
        (hdrs.SEC_WEBSOCKET_ACCEPT, base64.b64encode(
            hashlib.sha1(key.encode() + WS_KEY).digest()).decode())]

    notakeover = False
    if compress:
        extensions = headers.get(hdrs.SEC_WEBSOCKET_EXTENSIONS)
        # Server side always get return with no exception.
        # If something happened, just drop compress extension
        compress, notakeover = ws_ext_parse(extensions, isserver=True)
        if compress:
            enabledext = ws_ext_gen(compress=compress, isserver=True,
                                    server_notakeover=notakeover)
            response_headers.append((hdrs.SEC_WEBSOCKET_EXTENSIONS,
                                     enabledext))

    if protocol:
        response_headers.append((hdrs.SEC_WEBSOCKET_PROTOCOL, protocol))

    # response code, headers, None, writer, protocol
    return (101,
            response_headers,
            None,
            WebSocketWriter(
                stream, limit=write_buffer_size,
                compress=compress, notakeover=notakeover),
            protocol,
            compress)
