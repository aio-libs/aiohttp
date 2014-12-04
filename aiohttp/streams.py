__all__ = ['EofStream',
           'StreamReader', 'DataQueue', 'ChunksQueue',
           'FlowControlStreamReader', 'FlowControlDataQueue',
           'FlowControlChunksQueue']

import asyncio
import collections
import traceback

from .log import internal_logger

EOF_MARKER = b''
DEFAULT_LIMIT = 2 ** 16


class EofStream(Exception):
    """eof stream indication."""


class StreamReader(asyncio.StreamReader):

    total_bytes = 0

    def __init__(self, limit=DEFAULT_LIMIT, loop=None):
        self._limit = limit
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._buffer = bytearray()
        self._eof = False
        self._waiter = None
        self._eof_waiter = None
        self._exception = None

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
        self._eof_waiter = asyncio.Future(loop=self._loop)
        try:
            yield from self._eof_waiter
        finally:
            self._eof_waiter = None

    def feed_data(self, data):
        assert not self._eof, 'feed_data after feed_eof'

        if not data:
            return

        self._buffer.extend(data)
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
        return asyncio.Future(loop=self._loop)

    @asyncio.coroutine
    def readline(self):
        if self._exception is not None:
            raise self._exception

        line = bytearray()
        not_enough = True

        while not_enough:
            while self._buffer and not_enough:
                ichar = self._buffer.find(b'\n')
                if ichar < 0:
                    line.extend(self._buffer)
                    self._buffer.clear()
                else:
                    ichar += 1
                    line.extend(self._buffer[:ichar])
                    del self._buffer[:ichar]
                    not_enough = False

                if len(line) > self._limit:
                    raise ValueError('Line is too long')

            if self._eof:
                break

            if not_enough:
                self._waiter = self._create_waiter('readline')
                try:
                    yield from self._waiter
                finally:
                    self._waiter = None

        if line:
            return bytes(line)
        else:
            return EOF_MARKER

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
            # bytes.  So just call self.read(self._limit) until EOF.
            blocks = []
            while True:
                block = yield from self.read(self._limit)
                if not block:
                    break
                blocks.append(block)
            data = b''.join(blocks)
            if data:
                return data
            else:
                return EOF_MARKER
        else:
            if not self._buffer and not self._eof:
                self._waiter = self._create_waiter('read')
                try:
                    yield from self._waiter
                finally:
                    self._waiter = None

        if n < 0 or len(self._buffer) <= n:
            data = bytes(self._buffer)
            self._buffer.clear()
        else:
            # n > 0 and len(self._buffer) > n
            data = bytes(self._buffer[:n])
            del self._buffer[:n]

        if data:
            return data
        else:
            return EOF_MARKER

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

        data = bytes(self._buffer)
        del self._buffer[:]

        if data:
            return data
        else:
            return EOF_MARKER

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

    def read_nowait(self):
        if self._exception is not None:
            raise self._exception

        if self._waiter and not self._waiter.done():
            raise RuntimeError(
                'Called while some coroutine is waiting for incoming data.')

        if not self._buffer:
            return EOF_MARKER
        else:
            data = bytes(self._buffer)
            del self._buffer[:]
            return data


class FlowControlStreamReader(StreamReader):

    def __init__(self, stream, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._stream = stream

    @asyncio.coroutine
    def read(self, n=-1):
        self._stream.resume_stream()
        try:
            return (yield from super().read(n))
        finally:
            self._stream.pause_stream()

    @asyncio.coroutine
    def readline(self):
        self._stream.resume_stream()
        try:
            return (yield from super().readline())
        finally:
            self._stream.pause_stream()

    @asyncio.coroutine
    def readany(self):
        self._stream.resume_stream()
        try:
            return (yield from super().readany())
        finally:
            self._stream.pause_stream()

    @asyncio.coroutine
    def readexactly(self, n):
        self._stream.resume_stream()
        try:
            return (yield from super().readexactly(n))
        finally:
            self._stream.pause_stream()


class DataQueue:
    """DataQueue is a general-purpose blocking queue with one reader."""

    def __init__(self, *, loop=None):
        self._loop = loop
        self._buffer = collections.deque()
        self._eof = False
        self._waiter = None
        self._exception = None

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


class FlowControlDataQueue(DataQueue):
    """FlowControlDataQueue resumes and pauses an underlying stream.

    It is a destination for parsed data."""

    def __init__(self, stream, *, loop=None):
        super().__init__(loop=loop)

        self._stream = stream

    @asyncio.coroutine
    def read(self):
        self._stream.resume_stream()
        try:
            return (yield from super().read())
        finally:
            self._stream.pause_stream()


class ChunksQueue(DataQueue):
    """Like a :class:`DataQueue`, but for binary chunked data transfer."""

    @asyncio.coroutine
    def read(self):
        try:
            return (yield from super().read())
        except EofStream:
            return EOF_MARKER

    readany = read


class FlowControlChunksQueue(FlowControlDataQueue, ChunksQueue):
    """FlowControlChunksQueue resumes and pauses an underlying stream."""

    readany = FlowControlDataQueue.read
