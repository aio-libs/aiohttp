"""Parser is a generator function.

Parser receives data with generator's send() method and sends data to
destination DataQueue. Parser receives ParserBuffer and DataQueue objects
as a parameters of the parser call, all subsequent send() calls should
send bytes objects. Parser sends parsed `term` to desitnation buffer with
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

    1. StreamParser recevies eof with feed_eof() call.
    2. StreamParser throws EofStream exception into parser.
    3. Then it unsets parser.

_SocketSocketTransport ->
   -> "protocol" -> StreamParser -> "parser" -> DataQueue <- "application"

"""
__all__ = ['EofStream', 'StreamParser', 'StreamProtocol',
           'ParserBuffer', 'DataQueue', 'LinesParser', 'ChunksParser']

import asyncio
import asyncio.streams
import collections
import inspect
from . import errors

BUF_LIMIT = 2**14
DEFAULT_LIMIT = 2**16


class EofStream(Exception):
    """eof stream indication."""


class StreamParser:
    """StreamParser manages incoming bytes stream and protocol parsers.

    StreamParser uses ParserBuffer as internal buffer.

    set_parser() sets current parser, it creates DataQueue object
    and sends ParserBuffer and DataQueue into parser generator.

    unset_parser() sends EofStream into parser and then removes it.
    """

    def __init__(self, *, loop=None, buf=None,
                 paused=True, limit=DEFAULT_LIMIT):
        self._loop = loop
        self._eof = False
        self._exception = None
        self._parser = None
        self._transport = None
        self._limit = limit
        self._paused = False
        self._stream_paused = paused
        self._output = None
        self._buffer = buf if buf is not None else ParserBuffer()

    @property
    def output(self):
        return self._output

    def set_transport(self, transport):
        assert self._transport is None, 'Transport already set'
        self._transport = transport

    def at_eof(self):
        return self._eof

    def pause_stream(self):
        self._stream_paused = True

    def resume_stream(self):
        if self._paused and self._buffer.size <= self._limit:
            self._paused = False
            self._transport.resume_reading()

        self._stream_paused = False
        if self._parser and self._buffer:
            self.feed_data(b'')

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._exception = exc

        if self._output is not None:
            self._output.set_exception(exc)
            self._output = None
            self._parser = None

    def feed_data(self, data):
        """send data to current parser or store in buffer."""
        if data is None:
            return

        if self._parser and not self._stream_paused:
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

        if (self._transport is not None and not self._paused and
                self._buffer.size > 2*self._limit):
            try:
                self._transport.pause_reading()
            except NotImplementedError:
                # The transport can't be paused.
                # We'll just have to buffer all data.
                # Forget the transport so we don't keep trying.
                self._transport = None
            else:
                self._paused = True

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
                self._output.set_exception(errors.ConnectionError())
            except Exception as exc:
                self._output.set_exception(exc)

            self._parser = None
            self._output = None

        self._buffer.shrink()
        self._eof = True

    def set_parser(self, parser):
        """set parser to stream. return parser's DataQueue."""
        if self._parser:
            self.unset_parser()

        output = DataQueue(self, loop=self._loop)
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
        if self._buffer:
            self._buffer.shrink()

        if self._parser is None:
            return

        try:
            self._parser.throw(EofStream())
        except StopIteration:
            self._output.feed_eof()
        except EofStream:
            self._output.set_exception(errors.ConnectionError())
        except Exception as exc:
            self._output.set_exception(exc)
        finally:
            self._output = None
            self._parser = None


class StreamProtocol(asyncio.streams.FlowControlMixin, asyncio.Protocol):
    """Helper class to adapt between Protocol and StreamReader."""

    def __init__(self, *, loop=None, **kwargs):
        super().__init__(loop=loop)

        self.transport = None
        self.writer = None
        self.reader = StreamParser(loop=loop, **kwargs)

    def is_connected(self):
        return self.transport is not None

    def connection_made(self, transport):
        self.transport = transport
        self.reader.set_transport(transport)
        self.writer = asyncio.streams.StreamWriter(
            transport, self, self.reader, self._loop)

    def connection_lost(self, exc):
        self.transport = None

        if exc is None:
            self.reader.feed_eof()
        else:
            self.reader.set_exception(exc)

        super().connection_lost(exc)

    def data_received(self, data):
        self.reader.feed_data(data)

    def eof_received(self):
        self.reader.feed_eof()

    def _make_drain_waiter(self):
        if not self._paused:
            return ()
        waiter = self._drain_waiter
        if waiter is None or waiter.cancelled():
            waiter = asyncio.Future(loop=self._loop)
            self._drain_waiter = waiter
        return waiter


class DataQueue:
    """DataQueue is a destination for parsed data."""

    def __init__(self, stream, *, loop=None):
        self._stream = stream
        self._loop = loop
        self._buffer = collections.deque()
        self._eof = False
        self._waiter = None
        self._exception = None

    def at_eof(self):
        return self._eof

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._exception = exc

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_exception(exc)

    def feed_data(self, data):
        self._buffer.append(data)

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.cancelled():
                waiter.set_result(True)

    def feed_eof(self):
        self._eof = True

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.cancelled():
                waiter.set_result(False)

    @asyncio.coroutine
    def read(self):
        self._stream.resume_stream()
        try:
            if not self._buffer and not self._eof:
                if self._exception is not None:
                    raise self._exception

                assert not self._waiter
                self._waiter = asyncio.Future(loop=self._loop)
                yield from self._waiter

            if self._buffer:
                return self._buffer.popleft()
            else:
                if self._exception is not None:
                    raise self._exception
                else:
                    raise EofStream
        finally:
            self._stream.pause_stream()


class ParserBuffer(bytearray):
    """ParserBuffer is a bytearray extension.

    ParserBuffer provides helper methods for parsers.
    """

    def __init__(self, *args, limit=BUF_LIMIT):
        super().__init__(*args)

        self.offset = 0
        self.size = 0
        self._limit = limit
        self._exception = None
        self._writer = self._feed_data()
        next(self._writer)

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._exception = exc

    def shrink(self):
        if self.offset:
            del self[:self.offset]
            self.offset = 0
            self.size = len(self)

    def _feed_data(self):
        while True:
            chunk = yield
            if chunk:
                chunk_len = len(chunk)
                self.size += chunk_len
                self.extend(chunk)

            # shrink buffer
            if (self.offset and len(self) > self._limit):
                self.shrink()

            if self._exception:
                self._writer = self._feed_data()
                next(self._writer)
                raise self._exception

    def feed_data(self, data):
        self._writer.send(data)

    def read(self, size):
        """read() reads specified amount of bytes."""

        while True:
            if self.size >= size:
                start, end = self.offset, self.offset + size
                self.offset = end
                self.size = self.size - size
                return self[start:end]

            self._writer.send((yield))

    def readsome(self, size=None):
        """reads size of less amount of bytes."""

        while True:
            if self.size > 0:
                if size is None or self.size < size:
                    size = self.size

                start, end = self.offset, self.offset + size
                self.offset = end
                self.size = self.size - size

                return self[start:end]

            self._writer.send((yield))

    def readuntil(self, stop, limit=None):
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            pos = self.find(stop, self.offset)
            if pos >= 0:
                end = pos + stop_len
                size = end - self.offset
                if limit is not None and size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long.', limit)

                start, self.offset = self.offset, end
                self.size = self.size - size

                return self[start:end]
            else:
                if limit is not None and self.size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long.', limit)

            self._writer.send((yield))

    def wait(self, size):
        """wait() waits for specified amount of bytes
        then returns data without changing internal buffer."""

        while True:
            if self.size >= size:
                return self[self.offset:self.offset + size]

            self._writer.send((yield))

    def waituntil(self, stop, limit=None):
        """waituntil() reads until `stop` bytes sequence."""
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            pos = self.find(stop, self.offset)
            if pos >= 0:
                end = pos + stop_len
                size = end - self.offset
                if limit is not None and size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long. %s' % bytes(self), limit)

                return self[self.offset:end]
            else:
                if limit is not None and self.size > limit:
                    raise errors.LineLimitExceededParserError(
                        'Line is too long. %s' % bytes(self), limit)

            self._writer.send((yield))

    def skip(self, size):
        """skip() skips specified amount of bytes."""

        while self.size < size:
            self._writer.send((yield))

        self.size -= size
        self.offset += size

    def skipuntil(self, stop):
        """skipuntil() reads until `stop` bytes sequence."""
        assert isinstance(stop, bytes) and stop, \
            'bytes is required: {!r}'.format(stop)

        stop_len = len(stop)

        while True:
            stop_line = self.find(stop, self.offset)
            if stop_line >= 0:
                end = stop_line + stop_len
                self.size = self.size - (end - self.offset)
                self.offset = end
                return
            else:
                self.size = 0
                self.offset = len(self) - 1

            self._writer.send((yield))

    def __bytes__(self):
        return bytes(self[self.offset:])


class LinesParser:
    """Lines parser.

    Lines parser splits a bytes stream into a chunks of data, each chunk ends
    with \\n symbol."""

    def __init__(self, limit=2**16):
        self._limit = limit

    def __call__(self, out, buf):
        try:
            while True:
                out.feed_data((yield from buf.readuntil(b'\n', self._limit)))
        except EofStream:
            pass


class ChunksParser:
    """Chunks parser.

    Chunks parser splits a bytes stream into a specified
    size chunks of data."""

    def __init__(self, size=8196):
        self._size = size

    def __call__(self, out, buf):
        try:
            while True:
                out.feed_data((yield from buf.read(self._size)))
        except EofStream:
            pass
