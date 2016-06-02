import sys
import asyncio
import collections
import functools
import traceback

from .log import internal_logger
from . import helpers

__all__ = (
    'EofStream', 'StreamReader', 'DataQueue', 'ChunksQueue',
    'FlowControlStreamReader',
    'FlowControlDataQueue', 'FlowControlChunksQueue')

PY_35 = sys.version_info >= (3, 5)

EOF_MARKER = b''
DEFAULT_LIMIT = 2 ** 16


class EofStream(Exception):
    """eof stream indication."""


class AsyncStreamIterator:

    def __init__(self, read_func):
        self.read_func = read_func

    @asyncio.coroutine
    def __aiter__(self):
        return self

    @asyncio.coroutine
    def __anext__(self):
        try:
            rv = yield from self.read_func()
        except EofStream:
            raise StopAsyncIteration  # NOQA
        if rv == EOF_MARKER:
            raise StopAsyncIteration  # NOQA
        return rv


class AsyncStreamReaderMixin:

    if PY_35:
        @asyncio.coroutine
        def __aiter__(self):
            return AsyncStreamIterator(self.readline)

        def iter_chunked(self, n):
            """Returns an asynchronous iterator that yields chunks of size n.

            Python-3.5 available for Python 3.5+ only
            """
            return AsyncStreamIterator(lambda: self.read(n))

        def iter_any(self):
            """Returns an asynchronous iterator that yields slices of data
            as they come.

            Python-3.5 available for Python 3.5+ only
            """
            return AsyncStreamIterator(self.readany)


class StreamReader(asyncio.StreamReader, AsyncStreamReaderMixin):
    """An enhancement of :class:`asyncio.StreamReader`.

    Supports asynchronous iteration by line, chunk or as available::

        async for line in reader:
            ...
        async for chunk in reader.iter_chunked(1024):
            ...
        async for slice in reader.iter_any():
            ...

    .. automethod:: AsyncStreamReaderMixin.iter_chunked
    .. automethod:: AsyncStreamReaderMixin.iter_any
    """

    total_bytes = 0

    def __init__(self, limit=DEFAULT_LIMIT, loop=None):
        self._limit = limit
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._buffer = collections.deque()
        self._buffer_size = 0
        self._buffer_offset = 0
        self._eof = False
        self._waiter = None
        self._eof_waiter = None
        self._exception = None

    def __repr__(self):
        info = ['StreamReader']
        if self._buffer_size:
            info.append('%d bytes' % self._buffer_size)
        if self._eof:
            info.append('eof')
        if self._limit != DEFAULT_LIMIT:
            info.append('l=%d' % self._limit)
        if self._waiter:
            info.append('w=%r' % self._waiter)
        if self._exception:
            info.append('e=%r' % self._exception)
        return '<%s>' % ' '.join(info)

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._exception = exc

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.cancelled():
                waiter.set_exception(exc)

    def feed_eof(self):
        self._eof = True

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.cancelled():
                waiter.set_result(True)

        waiter = self._eof_waiter
        if waiter is not None:
            self._eof_waiter = None
            if not waiter.cancelled():
                waiter.set_result(True)

    def is_eof(self):
        """Return True if  'feed_eof' was called."""
        return self._eof

    def at_eof(self):
        """Return True if the buffer is empty and 'feed_eof' was called."""
        return self._eof and not self._buffer

    @asyncio.coroutine
    def wait_eof(self):
        if self._eof:
            return

        assert self._eof_waiter is None
        self._eof_waiter = helpers.create_future(self._loop)
        try:
            yield from self._eof_waiter
        finally:
            self._eof_waiter = None

    def unread_data(self, data):
        """ rollback reading some data from stream, inserting it to buffer head.
        """
        if not data:
            return

        if self._buffer_offset:
            self._buffer[0] = self._buffer[0][self._buffer_offset:]
            self._buffer_offset = 0
        self._buffer.appendleft(data)
        self._buffer_size += len(data)

    def feed_data(self, data):
        assert not self._eof, 'feed_data after feed_eof'

        if not data:
            return

        self._buffer.append(data)
        self._buffer_size += len(data)
        self.total_bytes += len(data)

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.cancelled():
                waiter.set_result(False)

    def _create_waiter(self, func_name):
        # StreamReader uses a future to link the protocol feed_data() method
        # to a read coroutine. Running two read coroutines at the same time
        # would have an unexpected behaviour. It would not possible to know
        # which coroutine would get the next data.
        if self._waiter is not None:
            raise RuntimeError('%s() called while another coroutine is '
                               'already waiting for incoming data' % func_name)
        return helpers.create_future(self._loop)

    @asyncio.coroutine
    def readline(self):
        if self._exception is not None:
            raise self._exception

        line = []
        line_size = 0
        not_enough = True

        while not_enough:
            while self._buffer and not_enough:
                offset = self._buffer_offset
                ichar = self._buffer[0].find(b'\n', offset) + 1
                # Read from current offset to found b'\n' or to the end.
                data = self._read_nowait(ichar - offset if ichar else 0)
                line.append(data)
                line_size += len(data)
                if ichar:
                    not_enough = False

                if line_size > self._limit:
                    raise ValueError('Line is too long')

            if self._eof:
                break

            if not_enough:
                self._waiter = self._create_waiter('readline')
                try:
                    yield from self._waiter
                finally:
                    self._waiter = None

        return b''.join(line)

    @asyncio.coroutine
    def read(self, n=-1):
        if self._exception is not None:
            raise self._exception

        # migration problem; with DataQueue you have to catch
        # EofStream exception, so common way is to run payload.read() inside
        # infinite loop. what can cause real infinite loop with StreamReader
        # lets keep this code one major release.
        if __debug__:
            if self._eof and not self._buffer:
                self._eof_counter = getattr(self, '_eof_counter', 0) + 1
                if self._eof_counter > 5:
                    stack = traceback.format_stack()
                    internal_logger.warning(
                        'Multiple access to StreamReader in eof state, '
                        'might be infinite loop: \n%s', stack)

        if not n:
            return EOF_MARKER

        if n < 0:
            # This used to just loop creating a new waiter hoping to
            # collect everything in self._buffer, but that would
            # deadlock if the subprocess sends more than self.limit
            # bytes.  So just call self.readany() until EOF.
            blocks = []
            while True:
                block = yield from self.readany()
                if not block:
                    break
                blocks.append(block)
            return b''.join(blocks)

        if not self._buffer and not self._eof:
            self._waiter = self._create_waiter('read')
            try:
                yield from self._waiter
            finally:
                self._waiter = None

        return self._read_nowait(n)

    @asyncio.coroutine
    def readany(self):
        if self._exception is not None:
            raise self._exception

        if not self._buffer and not self._eof:
            self._waiter = self._create_waiter('readany')
            try:
                yield from self._waiter
            finally:
                self._waiter = None

        return self._read_nowait()

    @asyncio.coroutine
    def readexactly(self, n):
        if self._exception is not None:
            raise self._exception

        # There used to be "optimized" code here.  It created its own
        # Future and waited until self._buffer had at least the n
        # bytes, then called read(n).  Unfortunately, this could pause
        # the transport if the argument was larger than the pause
        # limit (which is twice self._limit).  So now we just read()
        # into a local buffer.

        blocks = []
        while n > 0:
            block = yield from self.read(n)
            if not block:
                partial = b''.join(blocks)
                raise asyncio.streams.IncompleteReadError(
                    partial, len(partial) + n)
            blocks.append(block)
            n -= len(block)

        return b''.join(blocks)

    def read_nowait(self, n=None):
        if self._exception is not None:
            raise self._exception

        if self._waiter and not self._waiter.done():
            raise RuntimeError(
                'Called while some coroutine is waiting for incoming data.')

        return self._read_nowait(n)

    def _read_nowait(self, n=None):
        if not self._buffer:
            return EOF_MARKER

        first_buffer = self._buffer[0]
        offset = self._buffer_offset
        if n and len(first_buffer) - offset > n:
            data = first_buffer[offset:offset + n]
            self._buffer_offset += n

        elif offset:
            self._buffer.popleft()
            data = first_buffer[offset:]
            self._buffer_offset = 0

        else:
            data = self._buffer.popleft()

        self._buffer_size -= len(data)
        return data


class EmptyStreamReader(AsyncStreamReaderMixin):

    def exception(self):
        return None

    def set_exception(self, exc):
        pass

    def feed_eof(self):
        pass

    def is_eof(self):
        return True

    def at_eof(self):
        return True

    @asyncio.coroutine
    def wait_eof(self):
        return

    def feed_data(self, data):
        pass

    @asyncio.coroutine
    def readline(self):
        return EOF_MARKER

    @asyncio.coroutine
    def read(self, n=-1):
        return EOF_MARKER

    @asyncio.coroutine
    def readany(self):
        return EOF_MARKER

    @asyncio.coroutine
    def readexactly(self, n):
        raise asyncio.streams.IncompleteReadError(b'', n)

    def read_nowait(self):
        return EOF_MARKER


class DataQueue:
    """DataQueue is a general-purpose blocking queue with one reader."""

    def __init__(self, *, loop=None):
        self._loop = loop
        self._eof = False
        self._waiter = None
        self._exception = None
        self._size = 0
        self._buffer = collections.deque()

    def is_eof(self):
        return self._eof

    def at_eof(self):
        return self._eof and not self._buffer

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._exception = exc

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_exception(exc)

    def feed_data(self, data, size=0):
        self._size += size
        self._buffer.append((data, size))

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
        if not self._buffer and not self._eof:
            if self._exception is not None:
                raise self._exception

            assert not self._waiter
            self._waiter = helpers.create_future(self._loop)
            try:
                yield from self._waiter
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._waiter = None
                raise

        if self._buffer:
            data, size = self._buffer.popleft()
            self._size -= size
            return data
        else:
            if self._exception is not None:
                raise self._exception
            else:
                raise EofStream

    if PY_35:
        @asyncio.coroutine
        def __aiter__(self):
            return AsyncStreamIterator(self.read)


class ChunksQueue(DataQueue):
    """Like a :class:`DataQueue`, but for binary chunked data transfer."""

    @asyncio.coroutine
    def read(self):
        try:
            return (yield from super().read())
        except EofStream:
            return EOF_MARKER

    readany = read


def maybe_resume(func):

    @asyncio.coroutine
    @functools.wraps(func)
    def wrapper(self, *args, **kw):
        result = yield from func(self, *args, **kw)

        if self._stream.paused:
            if self._buffer_size < self._b_limit:
                try:
                    self._stream.transport.resume_reading()
                except (AttributeError, NotImplementedError):
                    pass
                else:
                    self._stream.paused = False
        else:
            if self._buffer_size > self._b_limit:
                try:
                    self._stream.transport.pause_reading()
                except (AttributeError, NotImplementedError):
                    pass
                else:
                    self._stream.paused = True

        return result

    return wrapper


class FlowControlStreamReader(StreamReader):

    def __init__(self, stream, limit=DEFAULT_LIMIT, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._stream = stream
        self._b_limit = limit * 2

        # resume transport reading
        if stream.paused:
            try:
                self._stream.transport.resume_reading()
            except (AttributeError, NotImplementedError):
                pass

    def feed_data(self, data, size=0):
        has_waiter = self._waiter is not None and not self._waiter.cancelled()

        super().feed_data(data)

        if (not self._stream.paused and
                not has_waiter and self._buffer_size > self._b_limit):
            try:
                self._stream.transport.pause_reading()
            except (AttributeError, NotImplementedError):
                pass
            else:
                self._stream.paused = True

    @maybe_resume
    def read(self, n=-1):
        return (yield from super().read(n))

    @maybe_resume
    def readline(self):
        return (yield from super().readline())

    @maybe_resume
    def readany(self):
        return (yield from super().readany())

    @maybe_resume
    def readexactly(self, n):
        return (yield from super().readexactly(n))


class FlowControlDataQueue(DataQueue):
    """FlowControlDataQueue resumes and pauses an underlying stream.

    It is a destination for parsed data."""

    def __init__(self, stream, *, limit=DEFAULT_LIMIT, loop=None):
        super().__init__(loop=loop)

        self._stream = stream
        self._limit = limit * 2

        # resume transport reading
        if stream.paused:
            try:
                self._stream.transport.resume_reading()
            except (AttributeError, NotImplementedError):
                pass
            else:
                self._stream.paused = False

    def feed_data(self, data, size):
        has_waiter = self._waiter is not None and not self._waiter.cancelled()

        super().feed_data(data, size)

        if (not self._stream.paused and
                not has_waiter and self._size > self._limit):
            try:
                self._stream.transport.pause_reading()
            except (AttributeError, NotImplementedError):
                pass
            else:
                self._stream.paused = True

    @asyncio.coroutine
    def read(self):
        result = yield from super().read()

        if self._stream.paused:
            if self._size < self._limit:
                try:
                    self._stream.transport.resume_reading()
                except (AttributeError, NotImplementedError):
                    pass
                else:
                    self._stream.paused = False
        else:
            if self._size > self._limit:
                try:
                    self._stream.transport.pause_reading()
                except (AttributeError, NotImplementedError):
                    pass
                else:
                    self._stream.paused = True

        return result


class FlowControlChunksQueue(FlowControlDataQueue):

    @asyncio.coroutine
    def read(self):
        try:
            return (yield from super().read())
        except EofStream:
            return EOF_MARKER

    readany = read
