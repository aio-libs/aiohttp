import asyncio
import collections
import traceback

from . import helpers
from .log import internal_logger


__all__ = (
    'EMPTY_PAYLOAD', 'EofStream', 'StreamReader', 'DataQueue', 'ChunksQueue',
    'FlowControlStreamReader',
    'FlowControlDataQueue', 'FlowControlChunksQueue')

DEFAULT_LIMIT = 2 ** 16


class EofStream(Exception):
    """eof stream indication."""


if helpers.PY_35:
    class AsyncStreamIterator:

        def __init__(self, read_func):
            self.read_func = read_func

        def __aiter__(self):
            return self

        if not helpers.PY_352:  # pragma: no cover
            __aiter__ = asyncio.coroutine(__aiter__)

        @asyncio.coroutine
        def __anext__(self):
            try:
                rv = yield from self.read_func()
            except EofStream:
                raise StopAsyncIteration  # NOQA
            if rv == b'':
                raise StopAsyncIteration  # NOQA
            return rv


class AsyncStreamReaderMixin:

    if helpers.PY_35:
        def __aiter__(self):
            return AsyncStreamIterator(self.readline)

        if not helpers.PY_352:  # pragma: no cover
            __aiter__ = asyncio.coroutine(__aiter__)

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

        def iter_chunks(self):
            """Returns an asynchronous iterator that yields chunks of the
            size as received by the server.

            Python-3.5 available for Python 3.5+ only
            """
            return AsyncStreamIterator(self.readchunk)


class StreamReader(AsyncStreamReaderMixin):
    """An enhancement of asyncio.StreamReader.

    Supports asynchronous iteration by line, chunk or as available::

        async for line in reader:
            ...
        async for chunk in reader.iter_chunked(1024):
            ...
        async for slice in reader.iter_any():
            ...

    """

    total_bytes = 0

    def __init__(self, limit=DEFAULT_LIMIT, timer=None, loop=None):
        self._limit = limit
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._size = 0
        self._buffer = collections.deque()
        self._buffer_offset = 0
        self._eof = False
        self._waiter = None
        self._eof_waiter = None
        self._exception = None
        self._timer = timer
        self._eof_callbacks = []

    def __repr__(self):
        info = [self.__class__.__name__]
        if self._size:
            info.append('%d bytes' % self._size)
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
        self._eof_callbacks.clear()

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_exception(exc)

        waiter = self._eof_waiter
        if waiter is not None:
            self._eof_waiter = None
            if not waiter.done():
                waiter.set_exception(exc)

    def on_eof(self, callback):
        if self._eof:
            try:
                callback()
            except Exception:
                internal_logger.exception('Exception in eof callback')
        else:
            self._eof_callbacks.append(callback)

    def feed_eof(self):
        self._eof = True

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_result(True)

        waiter = self._eof_waiter
        if waiter is not None:
            self._eof_waiter = None
            if not waiter.done():
                waiter.set_result(True)

        for cb in self._eof_callbacks:
            try:
                cb()
            except Exception:
                internal_logger.exception('Exception in eof callback')

        self._eof_callbacks.clear()

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
        self._size += len(data)
        self._buffer.appendleft(data)

    def feed_data(self, data):
        assert not self._eof, 'feed_data after feed_eof'

        if not data:
            return

        self._size += len(data)
        self._buffer.append(data)
        self.total_bytes += len(data)

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_result(False)

    @asyncio.coroutine
    def _wait(self, func_name):
        # StreamReader uses a future to link the protocol feed_data() method
        # to a read coroutine. Running two read coroutines at the same time
        # would have an unexpected behaviour. It would not possible to know
        # which coroutine would get the next data.
        if self._waiter is not None:
            raise RuntimeError('%s() called while another coroutine is '
                               'already waiting for incoming data' % func_name)

        waiter = self._waiter = helpers.create_future(self._loop)
        try:
            if self._timer:
                with self._timer:
                    yield from waiter
            else:
                yield from waiter
        finally:
            self._waiter = None

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
                data = self._read_nowait_chunk(ichar - offset if ichar else -1)
                line.append(data)
                line_size += len(data)
                if ichar:
                    not_enough = False

                if line_size > self._limit:
                    raise ValueError('Line is too long')

            if self._eof:
                break

            if not_enough:
                yield from self._wait('readline')

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
            return b''

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
            yield from self._wait('read')

        return self._read_nowait(n)

    @asyncio.coroutine
    def readany(self):
        if self._exception is not None:
            raise self._exception

        if not self._buffer and not self._eof:
            yield from self._wait('readany')

        return self._read_nowait(-1)

    @asyncio.coroutine
    def readchunk(self):
        if self._exception is not None:
            raise self._exception

        if not self._buffer and not self._eof:
            yield from self._wait('readchunk')

        return self._read_nowait_chunk(-1)

    @asyncio.coroutine
    def readexactly(self, n):
        if self._exception is not None:
            raise self._exception

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

    def read_nowait(self, n=-1):
        # default was changed to be consistent with .read(-1)
        #
        # I believe the most users don't know about the method and
        # they are not affected.
        if self._exception is not None:
            raise self._exception

        if self._waiter and not self._waiter.done():
            raise RuntimeError(
                'Called while some coroutine is waiting for incoming data.')

        return self._read_nowait(n)

    def _read_nowait_chunk(self, n):
        first_buffer = self._buffer[0]
        offset = self._buffer_offset
        if n != -1 and len(first_buffer) - offset > n:
            data = first_buffer[offset:offset + n]
            self._buffer_offset += n

        elif offset:
            self._buffer.popleft()
            data = first_buffer[offset:]
            self._buffer_offset = 0

        else:
            data = self._buffer.popleft()

        self._size -= len(data)
        return data

    def _read_nowait(self, n):
        chunks = []

        while self._buffer:
            chunk = self._read_nowait_chunk(n)
            chunks.append(chunk)
            if n != -1:
                n -= len(chunk)
                if n == 0:
                    break

        return b''.join(chunks) if chunks else b''


class EmptyStreamReader(AsyncStreamReaderMixin):

    def exception(self):
        return None

    def set_exception(self, exc):
        pass

    def on_eof(self, callback):
        try:
            callback()
        except Exception:
            internal_logger.exception('Exception in eof callback')

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
        return b''

    @asyncio.coroutine
    def read(self, n=-1):
        return b''

    @asyncio.coroutine
    def readany(self):
        return b''

    @asyncio.coroutine
    def readchunk(self):
        return b''

    @asyncio.coroutine
    def readexactly(self, n):
        raise asyncio.streams.IncompleteReadError(b'', n)

    def read_nowait(self):
        return b''


EMPTY_PAYLOAD = EmptyStreamReader()


class DataQueue:
    """DataQueue is a general-purpose blocking queue with one reader."""

    def __init__(self, *, loop=None):
        self._loop = loop
        self._eof = False
        self._waiter = None
        self._exception = None
        self._size = 0
        self._buffer = collections.deque()

    def __len__(self):
        return len(self._buffer)

    def is_eof(self):
        return self._eof

    def at_eof(self):
        return self._eof and not self._buffer

    def exception(self):
        return self._exception

    def set_exception(self, exc):
        self._eof = True
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

    if helpers.PY_35:
        def __aiter__(self):
            return AsyncStreamIterator(self.read)

        if not helpers.PY_352:  # pragma: no cover
            __aiter__ = asyncio.coroutine(__aiter__)


class ChunksQueue(DataQueue):
    """Like a :class:`DataQueue`, but for binary chunked data transfer."""

    @asyncio.coroutine
    def read(self):
        try:
            return (yield from super().read())
        except EofStream:
            return b''

    readany = read


class FlowControlStreamReader(StreamReader):

    def __init__(self, protocol, buffer_limit=DEFAULT_LIMIT, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._protocol = protocol
        self._b_limit = buffer_limit * 2

    def feed_data(self, data, size=0):
        super().feed_data(data)

        if self._size > self._b_limit and not self._protocol._reading_paused:
            self._protocol.pause_reading()

    @asyncio.coroutine
    def read(self, n=-1):
        try:
            return (yield from super().read(n))
        finally:
            if self._size < self._b_limit and self._protocol._reading_paused:
                self._protocol.resume_reading()

    @asyncio.coroutine
    def readline(self):
        try:
            return (yield from super().readline())
        finally:
            if self._size < self._b_limit and self._protocol._reading_paused:
                self._protocol.resume_reading()

    @asyncio.coroutine
    def readany(self):
        try:
            return (yield from super().readany())
        finally:
            if self._size < self._b_limit and self._protocol._reading_paused:
                self._protocol.resume_reading()

    @asyncio.coroutine
    def readchunk(self):
        try:
            return (yield from super().readchunk())
        finally:
            if self._size < self._b_limit and self._protocol._reading_paused:
                self._protocol.resume_reading()

    @asyncio.coroutine
    def readexactly(self, n):
        try:
            return (yield from super().readexactly(n))
        finally:
            if self._size < self._b_limit and self._protocol._reading_paused:
                self._protocol.resume_reading()

    def read_nowait(self, n=-1):
        try:
            return super().read_nowait(n)
        finally:
            if self._size < self._b_limit and self._protocol._reading_paused:
                self._protocol.resume_reading()


class FlowControlDataQueue(DataQueue):
    """FlowControlDataQueue resumes and pauses an underlying stream.

    It is a destination for parsed data."""

    def __init__(self, protocol, *, limit=DEFAULT_LIMIT, loop=None):
        super().__init__(loop=loop)

        self._protocol = protocol
        self._limit = limit * 2

    def feed_data(self, data, size):
        super().feed_data(data, size)

        if self._size > self._limit and not self._protocol._reading_paused:
            self._protocol.pause_reading()

    @asyncio.coroutine
    def read(self):
        try:
            return (yield from super().read())
        finally:
            if self._size < self._limit and self._protocol._reading_paused:
                self._protocol.resume_reading()


class FlowControlChunksQueue(FlowControlDataQueue):

    @asyncio.coroutine
    def read(self):
        try:
            return (yield from super().read())
        except EofStream:
            return b''

    readany = read
