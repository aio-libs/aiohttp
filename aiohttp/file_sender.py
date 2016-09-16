import asyncio
import mimetypes
import os

from . import hdrs
from .helpers import create_future
from .web_reqrep import StreamResponse


class FileSender:
    """"A helper that can be used to send files.
    """

    def __init__(self, *, resp_factory=StreamResponse, chunk_size=256*1024):
        self._response_factory = resp_factory
        self._chunk_size = chunk_size
        if bool(os.environ.get("AIOHTTP_NOSENDFILE")):
            self._sendfile = self._sendfile_fallback

    def _sendfile_cb(self, fut, out_fd, in_fd, offset,
                     count, loop, registered):
        if registered:
            loop.remove_writer(out_fd)
        if fut.cancelled():
            return
        try:
            n = os.sendfile(out_fd, in_fd, offset, count)
            if n == 0:  # EOF reached
                n = count
        except (BlockingIOError, InterruptedError):
            n = 0
        except Exception as exc:
            fut.set_exception(exc)
            return

        if n < count:
            loop.add_writer(out_fd, self._sendfile_cb, fut, out_fd, in_fd,
                            offset + n, count - n, loop, True)
        else:
            fut.set_result(None)

    @asyncio.coroutine
    def _sendfile_system(self, request, resp, fobj, count):
        # Write count bytes of fobj to resp using
        # the os.sendfile system call.
        #
        # request should be a aiohttp.web.Request instance.
        #
        # resp should be a aiohttp.web.StreamResponse instance.
        #
        # fobj should be an open file object.
        #
        # count should be an integer > 0.

        transport = request.transport

        if transport.get_extra_info("sslcontext"):
            yield from self._sendfile_fallback(request, resp, fobj, count)
            return

        def _send_headers(resp_impl):
            # Durty hack required for
            # https://github.com/KeepSafe/aiohttp/issues/1093
            # don't send headers in sendfile mode
            pass

        resp._send_headers = _send_headers

        @asyncio.coroutine
        def write_eof():
            # Durty hack required for
            # https://github.com/KeepSafe/aiohttp/issues/1177
            # do nothing in write_eof
            pass

        resp.write_eof = write_eof

        resp_impl = yield from resp.prepare(request)

        loop = request.app.loop
        # See https://github.com/KeepSafe/aiohttp/issues/958 for details

        # send headers
        headers = ['HTTP/{0.major}.{0.minor} 200 OK\r\n'.format(
            request.version)]
        for hdr, val in resp.headers.items():
            headers.append('{}: {}\r\n'.format(hdr, val))
        headers.append('\r\n')

        out_socket = transport.get_extra_info("socket").dup()
        out_socket.setblocking(False)
        out_fd = out_socket.fileno()
        in_fd = fobj.fileno()

        bheaders = ''.join(headers).encode('utf-8')
        headers_length = len(bheaders)
        resp_impl.headers_length = headers_length
        resp_impl.output_length = headers_length + count

        try:
            yield from loop.sock_sendall(out_socket, bheaders)
            fut = create_future(loop)
            self._sendfile_cb(fut, out_fd, in_fd, 0, count, loop, False)

            yield from fut
        finally:
            out_socket.close()

    @asyncio.coroutine
    def _sendfile_fallback(self, request, resp, fobj, count):
        # Mimic the _sendfile_system() method, but without using the
        # os.sendfile() system call. This should be used on systems
        # that don't support the os.sendfile().

        # To avoid blocking the event loop & to keep memory usage low,
        # fobj is transferred in chunks controlled by the
        # constructor's chunk_size argument.

        yield from resp.prepare(request)

        chunk_size = self._chunk_size

        chunk = fobj.read(chunk_size)
        while True:
            resp.write(chunk)
            yield from resp.drain()
            count = count - chunk_size
            if count <= 0:
                break
            chunk = fobj.read(count)

    if hasattr(os, "sendfile"):  # pragma: no cover
        _sendfile = _sendfile_system
    else:  # pragma: no cover
        _sendfile = _sendfile_fallback

    @asyncio.coroutine
    def send(self, request, filepath):
        """Send filepath to client using request."""
        st = filepath.stat()

        modsince = request.if_modified_since
        if modsince is not None and st.st_mtime <= modsince.timestamp():
            from .web_exceptions import HTTPNotModified
            raise HTTPNotModified()

        ct, encoding = mimetypes.guess_type(str(filepath))
        if not ct:
            ct = 'application/octet-stream'

        resp = self._response_factory()
        resp.content_type = ct
        if encoding:
            resp.headers[hdrs.CONTENT_ENCODING] = encoding
        resp.last_modified = st.st_mtime

        file_size = st.st_size

        resp.content_length = file_size
        resp.set_tcp_cork(True)
        try:
            with filepath.open('rb') as f:
                yield from self._sendfile(request, resp, f, file_size)

        finally:
            resp.set_tcp_nodelay(True)

        return resp
