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
             msg = yield form output.read()
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
from . import errors
from .streams import FlowControlDataQueue, EofStream

__all__ = ('EofStream', 'StreamParser', 'StreamProtocol',
           'ParserBuffer', 'LinesParser', 'ChunksParser')

DEFAULT_LIMIT = 2 ** 16


class StreamParser:
    """StreamParser manages incoming bytes stream and protocol parsers.

    StreamParser uses ParserBuffer as internal buffer.

    set_parser() sets current parser, it creates DataQueue object
    and sends ParserBuffer and DataQueue into parser generator.

    unset_parser() sends EofStream into parser and then removes it.
    """

    def __init__(self, *, loop=None, buf=None,
                 limit=DEFAULT_LIMIT, eof_exc_class=RuntimeError):
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
        if hasattr(self._loop, 'is_closed'):
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


class ParserBuffer(bytearray):
    """ParserBuffer is a bytearray extension.

    ParserBuffer provides helper methods for parsers.
    """
    __slots__ = ('_exception', '_writer')

    def __init__(self, *args):
        super().__init__(*args)

        self._exception = None
        self._writer = self._feed_data()
        next(self._writer)

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._exception = exc

    def _feed_data(self):
        while True:
            chunk = yield
            if chunk:
                self.extend(chunk)

            if self._exception:
                self._writer = self._feed_data()
                next(self._writer)
                raise self._exception

    def feed_data(self, data):
        self._writer.send(data)

    def read(self, size):
        """read() reads specified amount of bytes."""

        while True:
            if len(self) >= size:
                data = self[:size]
                del self[:size]
                return data

            self._writer.send((yield))

    def readsome(self, size=None):
        """reads size of less amount of bytes."""

        while True:
            length = len(self)
            if length > 0:
                if size is None or length < size:
                    size = length

                data = self[:size]
                del self[:size]
                return data

            self._writer.send((yield))

    def readuntil(self, stop, limit=None):
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            pos = self.find(stop)
            if pos >= 0:
                end = pos + stop_len
                size = end
                if limit is not None and size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long.', limit)

                data = self[:size]
                del self[:size]
                return data
            else:
                if limit is not None and len(self) > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long.', limit)

            self._writer.send((yield))

    def wait(self, size):
        """wait() waits for specified amount of bytes
        then returns data without changing internal buffer."""

        while True:
            if len(self) >= size:
                return self[:size]

            self._writer.send((yield))

    def waituntil(self, stop, limit=None):
        """waituntil() reads until `stop` bytes sequence."""
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            pos = self.find(stop)
            if pos >= 0:
                size = pos + stop_len
                if limit is not None and size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long. %s' % bytes(self), limit)

                return self[:size]
            else:
                if limit is not None and len(self) > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long. %s' % bytes(self), limit)

            self._writer.send((yield))

    def skip(self, size):
        """skip() skips specified amount of bytes."""

        while len(self) < size:
            self._writer.send((yield))

        del self[:size]

    def skipuntil(self, stop):
        """skipuntil() reads until `stop` bytes sequence."""
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            stop_line = self.find(stop)
            if stop_line >= 0:
                size = stop_line + stop_len
                del self[:size]
                return

            self._writer.send((yield))


class LinesParser:
    """Lines parser.

    Lines parser splits a bytes stream into a chunks of data, each chunk ends
    with \\n symbol."""

    def __init__(self, limit=DEFAULT_LIMIT):
        self._limit = limit

    def __call__(self, out, buf):
        try:
            while True:
                chunk = yield from buf.readuntil(b'\n', self._limit)
                out.feed_data(chunk, len(chunk))
        except EofStream:
            pass


class ChunksParser:
    """Chunks parser.

    Chunks parser splits a bytes stream into a specified
    size chunks of data."""

    def __init__(self, size=8192):
        self._size = size

    def __call__(self, out, buf):
        try:
            while True:
                chunk = yield from buf.read(self._size)
                out.feed_data(chunk, len(chunk))
        except EofStream:
            pass
