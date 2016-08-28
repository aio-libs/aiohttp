"""Parser is a generator function (NOT coroutine).

Parser receives data with generator's send() method and sends data to
destination DataQueue. Parser receives ParserBuffer and DataQueue objects
as a parameters of the parser call, all subsequent send() calls should
send bytes objects. Parser sends parsed `term` to destination buffer with
DataQueue.feed_data() method. DataQueue object should implement two methods.
feed_data() - parser uses this method to send parsed protocol data.
feed_eof() - parser uses this method for indication of end of parsing stream.
To indicate end of incoming data stream EofStream exception should be sent
into parser. Parser could throw exceptions.

There are three stages:

 * Data flow chain:

    1. Application creates StreamParser object for storing incoming data.
    2. StreamParser creates ParserBuffer as internal data buffer.
    3. Application create parser and set it into stream buffer:

        parser = HttpRequestParser()
        data_queue = stream.set_parser(parser)

    3. At this stage StreamParser creates DataQueue object and passes it
       and internal buffer into parser as an arguments.

        def set_parser(self, parser):
            output = DataQueue()
            self.p = parser(output, self._input)
            return output

    4. Application waits data on output.read()

        while True:
             msg = yield from output.read()
             ...

 * Data flow:

    1. asyncio's transport reads data from socket and sends data to protocol
       with data_received() call.
    2. Protocol sends data to StreamParser with feed_data() call.
    3. StreamParser sends data into parser with generator's send() method.
    4. Parser processes incoming data and sends parsed data
       to DataQueue with feed_data()
    5. Application received parsed data from DataQueue.read()

 * Eof:

    1. StreamParser receives eof with feed_eof() call.
    2. StreamParser throws EofStream exception into parser.
    3. Then it unsets parser.

_SocketSocketTransport ->
   -> "protocol" -> StreamParser -> "parser" -> DataQueue <- "application"

"""

import asyncio
import asyncio.streams
import inspect
import socket

from . import errors
from .streams import EofStream, FlowControlDataQueue

__all__ = ('EofStream', 'StreamParser', 'StreamProtocol',
           'ParserBuffer', 'StreamWriter')

DEFAULT_LIMIT = 2 ** 16

if hasattr(socket, 'TCP_CORK'):  # pragma: no cover
    CORK = socket.TCP_CORK
elif hasattr(socket, 'TCP_NOPUSH'):  # pragma: no cover
    CORK = socket.TCP_NOPUSH
else:  # pragma: no cover
    CORK = None


class StreamParser:
    """StreamParser manages incoming bytes stream and protocol parsers.

    StreamParser uses ParserBuffer as internal buffer.

    set_parser() sets current parser, it creates DataQueue object
    and sends ParserBuffer and DataQueue into parser generator.

    unset_parser() sends EofStream into parser and then removes it.
    """

    def __init__(self, *, loop=None, buf=None,
                 limit=DEFAULT_LIMIT, eof_exc_class=RuntimeError, **kwargs):
        self._loop = loop
        self._eof = False
        self._exception = None
        self._parser = None
        self._output = None
        self._limit = limit
        self._eof_exc_class = eof_exc_class
        self._buffer = buf if buf is not None else ParserBuffer()

        self.paused = False
        self.transport = None

    @property
    def output(self):
        return self._output

    def set_transport(self, transport):
        assert transport is None or self.transport is None, \
            'Transport already set'
        self.transport = transport

    def at_eof(self):
        return self._eof

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        if isinstance(exc, ConnectionError):
            exc, old_exc = self._eof_exc_class(), exc
            exc.__cause__ = old_exc
            exc.__context__ = old_exc

        self._exception = exc

        if self._output is not None:
            self._output.set_exception(exc)
            self._output = None
            self._parser = None

    def feed_data(self, data):
        """send data to current parser or store in buffer."""
        if data is None:
            return

        if self._parser:
            try:
                self._parser.send(data)
            except StopIteration:
                self._output.feed_eof()
                self._output = None
                self._parser = None
            except Exception as exc:
                self._output.set_exception(exc)
                self._output = None
                self._parser = None
        else:
            self._buffer.feed_data(data)

    def feed_eof(self):
        """send eof to all parsers, recursively."""
        if self._parser:
            try:
                if self._buffer:
                    self._parser.send(b'')
                self._parser.throw(EofStream())
            except StopIteration:
                self._output.feed_eof()
            except EofStream:
                self._output.set_exception(self._eof_exc_class())
            except Exception as exc:
                self._output.set_exception(exc)

            self._parser = None
            self._output = None

        self._eof = True

    def set_parser(self, parser, output=None):
        """set parser to stream. return parser's DataQueue."""
        if self._parser:
            self.unset_parser()

        if output is None:
            output = FlowControlDataQueue(
                self, limit=self._limit, loop=self._loop)

        if self._exception:
            output.set_exception(self._exception)
            return output

        # init parser
        p = parser(output, self._buffer)
        assert inspect.isgenerator(p), 'Generator is required'

        try:
            # initialize parser with data and parser buffers
            next(p)
        except StopIteration:
            pass
        except Exception as exc:
            output.set_exception(exc)
        else:
            # parser still require more data
            self._parser = p
            self._output = output

            if self._eof:
                self.unset_parser()

        return output

    def unset_parser(self):
        """unset parser, send eof to the parser and then remove it."""
        if self._parser is None:
            return

        # TODO: write test
        if self._loop.is_closed():
            # TODO: log something
            return

        try:
            self._parser.throw(EofStream())
        except StopIteration:
            self._output.feed_eof()
        except EofStream:
            self._output.set_exception(self._eof_exc_class())
        except Exception as exc:
            self._output.set_exception(exc)
        finally:
            self._output = None
            self._parser = None


class StreamWriter(asyncio.streams.StreamWriter):

    def __init__(self, transport, protocol, reader, loop):
        self._transport = transport
        self._protocol = protocol
        self._reader = reader
        self._loop = loop
        self._tcp_nodelay = False
        self._tcp_cork = False
        self._socket = transport.get_extra_info('socket')

    @property
    def tcp_nodelay(self):
        return self._tcp_nodelay

    def set_tcp_nodelay(self, value):
        value = bool(value)
        if self._tcp_nodelay == value:
            return
        self._tcp_nodelay = value
        if self._socket is None:
            return
        if self._socket.family not in (socket.AF_INET, socket.AF_INET6):
            return
        if self._tcp_cork:
            self._tcp_cork = False
            if CORK is not None:  # pragma: no branch
                self._socket.setsockopt(socket.IPPROTO_TCP, CORK, False)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, value)

    @property
    def tcp_cork(self):
        return self._tcp_cork

    def set_tcp_cork(self, value):
        value = bool(value)
        if self._tcp_cork == value:
            return
        self._tcp_cork = value
        if self._socket is None:
            return
        if self._socket.family not in (socket.AF_INET, socket.AF_INET6):
            return
        if self._tcp_nodelay:
            self._socket.setsockopt(socket.IPPROTO_TCP,
                                    socket.TCP_NODELAY,
                                    False)
            self._tcp_nodelay = False
        if CORK is not None:  # pragma: no branch
            self._socket.setsockopt(socket.IPPROTO_TCP, CORK, value)


class StreamProtocol(asyncio.streams.FlowControlMixin, asyncio.Protocol):
    """Helper class to adapt between Protocol and StreamReader."""

    def __init__(self, *, loop=None, disconnect_error=RuntimeError, **kwargs):
        super().__init__(loop=loop)

        self.transport = None
        self.writer = None
        self.reader = StreamParser(
            loop=loop, eof_exc_class=disconnect_error, **kwargs)

    def is_connected(self):
        return self.transport is not None

    def connection_made(self, transport):
        self.transport = transport
        self.reader.set_transport(transport)
        self.writer = StreamWriter(transport, self, self.reader, self._loop)

    def connection_lost(self, exc):
        self.transport = self.writer = None
        self.reader.set_transport(None)

        if exc is None:
            self.reader.feed_eof()
        else:
            self.reader.set_exception(exc)

        super().connection_lost(exc)

    def data_received(self, data):
        self.reader.feed_data(data)

    def eof_received(self):
        self.reader.feed_eof()


class _ParserBufferHelper:

    __slots__ = ('exception', 'data')

    def __init__(self, exception, data):
        self.exception = exception
        self.data = data


class ParserBuffer:
    """ParserBuffer is NOT a bytearray extension anymore.

    ParserBuffer provides helper methods for parsers.
    """
    __slots__ = ('_helper', '_writer', '_data')

    def __init__(self, *args):
        self._data = bytearray(*args)
        self._helper = _ParserBufferHelper(None, self._data)
        self._writer = self._feed_data(self._helper)
        next(self._writer)

    def exception(self):
        return self._helper.exception

    def set_exception(self, exc):
        self._helper.exception = exc

    @staticmethod
    def _feed_data(helper):
        while True:
            chunk = yield
            if chunk:
                helper.data.extend(chunk)

            if helper.exception:
                raise helper.exception

    def feed_data(self, data):
        if not self._helper.exception:
            self._writer.send(data)

    def read(self, size):
        """read() reads specified amount of bytes."""

        while True:
            if self._helper.exception:
                raise self._helper.exception

            if len(self._data) >= size:
                data = self._data[:size]
                del self._data[:size]
                return data

            self._writer.send((yield))

    def readsome(self, size=None):
        """reads size of less amount of bytes."""

        while True:
            if self._helper.exception:
                raise self._helper.exception

            length = len(self._data)
            if length > 0:
                if size is None or length < size:
                    size = length

                data = self._data[:size]
                del self._data[:size]
                return data

            self._writer.send((yield))

    def readuntil(self, stop, limit=None):
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            if self._helper.exception:
                raise self._helper.exception

            pos = self._data.find(stop)
            if pos >= 0:
                end = pos + stop_len
                size = end
                if limit is not None and size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long.', limit)

                data = self._data[:size]
                del self._data[:size]
                return data
            else:
                if limit is not None and len(self._data) > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long.', limit)

            self._writer.send((yield))

    def wait(self, size):
        """wait() waits for specified amount of bytes
        then returns data without changing internal buffer."""

        while True:
            if self._helper.exception:
                raise self._helper.exception

            if len(self._data) >= size:
                return self._data[:size]

            self._writer.send((yield))

    def waituntil(self, stop, limit=None):
        """waituntil() reads until `stop` bytes sequence."""
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            if self._helper.exception:
                raise self._helper.exception

            pos = self._data.find(stop)
            if pos >= 0:
                size = pos + stop_len
                if limit is not None and size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long. %s' % bytes(self._data), limit)

                return self._data[:size]
            else:
                if limit is not None and len(self._data) > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long. %s' % bytes(self._data), limit)

            self._writer.send((yield))

    def skip(self, size):
        """skip() skips specified amount of bytes."""

        while len(self._data) < size:
            if self._helper.exception:
                raise self._helper.exception

            self._writer.send((yield))

        del self._data[:size]

    def skipuntil(self, stop):
        """skipuntil() reads until `stop` bytes sequence."""
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            if self._helper.exception:
                raise self._helper.exception

            stop_line = self._data.find(stop)
            if stop_line >= 0:
                size = stop_line + stop_len
                del self._data[:size]
                return

            self._writer.send((yield))

    def extend(self, data):
        self._data.extend(data)

    def __len__(self):
        return len(self._data)

    def __bytes__(self):
        return bytes(self._data)
