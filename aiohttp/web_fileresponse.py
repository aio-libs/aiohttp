import mimetypes
import os
import pathlib

from . import hdrs
from .helpers import set_exception, set_result
from .http_writer import StreamWriter
from .log import server_logger
from .web_exceptions import (HTTPNotModified, HTTPOk, HTTPPartialContent,
                             HTTPPreconditionFailed,
                             HTTPRequestRangeNotSatisfiable)
from .web_response import StreamResponse


__all__ = ('FileResponse',)


NOSENDFILE = bool(os.environ.get("AIOHTTP_NOSENDFILE"))


class SendfileStreamWriter(StreamWriter):

    def __init__(self, *args, **kwargs):
        self._sendfile_buffer = []
        super().__init__(*args, **kwargs)

    def _write(self, chunk):
        # we overwrite StreamWriter._write, so nothing can be appended to
        # _buffer, and nothing is written to the transport directly by the
        # parent class
        self.output_size += len(chunk)
        self._sendfile_buffer.append(chunk)

    def _sendfile_cb(self, fut, out_fd, in_fd,
                     offset, count, loop, registered):
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
            set_exception(fut, exc)
            return

        if n < count:
            loop.add_writer(out_fd, self._sendfile_cb, fut, out_fd, in_fd,
                            offset + n, count - n, loop, True)
        else:
            set_result(fut, None)

    async def sendfile(self, fobj, count):
        out_socket = self.transport.get_extra_info('socket').dup()
        out_socket.setblocking(False)
        out_fd = out_socket.fileno()
        in_fd = fobj.fileno()
        offset = fobj.tell()

        loop = self.loop
        data = b''.join(self._sendfile_buffer)
        try:
            await loop.sock_sendall(out_socket, data)
            fut = loop.create_future()
            self._sendfile_cb(fut, out_fd, in_fd, offset, count, loop, False)
            await fut
        except Exception:
            server_logger.debug('Socket error')
            self.transport.close()
        finally:
            out_socket.close()

        self.output_size += count
        await super().write_eof()

    async def write_eof(self, chunk=b''):
        pass


class FileResponse(StreamResponse):
    """A response object can be used to send files."""

    def __init__(self, path, chunk_size=256*1024, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if isinstance(path, str):
            path = pathlib.Path(path)

        self._path = path
        self._chunk_size = chunk_size

    async def _sendfile_system(self, request, fobj, count):
        # Write count bytes of fobj to resp using
        # the os.sendfile system call.
        #
        # For details check
        # https://github.com/KeepSafe/aiohttp/issues/1177
        # See https://github.com/KeepSafe/aiohttp/issues/958 for details
        #
        # request should be a aiohttp.web.Request instance.
        # fobj should be an open file object.
        # count should be an integer > 0.

        transport = request.transport
        if (transport.get_extra_info("sslcontext") or
                transport.get_extra_info("socket") is None or
                self.compression):
            writer = await self._sendfile_fallback(request, fobj, count)
        else:
            writer = SendfileStreamWriter(
                request.protocol,
                request.loop
            )
            request._payload_writer = writer

            await super().prepare(request)
            await writer.sendfile(fobj, count)

        return writer

    async def _sendfile_fallback(self, request, fobj, count):
        # Mimic the _sendfile_system() method, but without using the
        # os.sendfile() system call. This should be used on systems
        # that don't support the os.sendfile().

        # To avoid blocking the event loop & to keep memory usage low,
        # fobj is transferred in chunks controlled by the
        # constructor's chunk_size argument.

        writer = await super().prepare(request)

        chunk_size = self._chunk_size

        chunk = fobj.read(chunk_size)
        while True:
            await writer.write(chunk)
            count = count - chunk_size
            if count <= 0:
                break
            chunk = fobj.read(min(chunk_size, count))

        await writer.drain()
        return writer

    if hasattr(os, "sendfile") and not NOSENDFILE:  # pragma: no cover
        _sendfile = _sendfile_system
    else:  # pragma: no cover
        _sendfile = _sendfile_fallback

    async def prepare(self, request):
        filepath = self._path

        gzip = False
        if 'gzip' in request.headers.get(hdrs.ACCEPT_ENCODING, ''):
            gzip_path = filepath.with_name(filepath.name + '.gz')

            if gzip_path.is_file():
                filepath = gzip_path
                gzip = True

        st = filepath.stat()

        modsince = request.if_modified_since
        if modsince is not None and st.st_mtime <= modsince.timestamp():
            self.set_status(HTTPNotModified.status_code)
            self._length_check = False
            # Delete any Content-Length headers provided by user. HTTP 304
            # should always have empty response body
            return await super().prepare(request)

        unmodsince = request.if_unmodified_since
        if unmodsince is not None and st.st_mtime > unmodsince.timestamp():
            self.set_status(HTTPPreconditionFailed.status_code)
            return await super().prepare(request)

        if hdrs.CONTENT_TYPE not in self.headers:
            ct, encoding = mimetypes.guess_type(str(filepath))
            if not ct:
                ct = 'application/octet-stream'
            should_set_ct = True
        else:
            encoding = 'gzip' if gzip else None
            should_set_ct = False

        status = HTTPOk.status_code
        file_size = st.st_size
        count = file_size

        start = None

        ifrange = request.if_range
        if ifrange is None or st.st_mtime <= ifrange.timestamp():
            # If-Range header check:
            # condition = cached date >= last modification date
            # return 206 if True else 200.
            # if False:
            #   Range header would not be processed, return 200
            # if True but Range header missing
            #   return 200
            try:
                rng = request.http_range
                start = rng.start
                end = rng.stop
            except ValueError:
                # https://tools.ietf.org/html/rfc7233:
                # A server generating a 416 (Range Not Satisfiable) response to
                # a byte-range request SHOULD send a Content-Range header field
                # with an unsatisfied-range value.
                # The complete-length in a 416 response indicates the current
                # length of the selected representation.
                #
                # Will do the same below. Many servers ignore this and do not
                # send a Content-Range header with HTTP 416
                self.headers[hdrs.CONTENT_RANGE] = 'bytes */{0}'.format(
                    file_size)
                self.set_status(HTTPRequestRangeNotSatisfiable.status_code)
                return await super().prepare(request)

            # If a range request has been made, convert start, end slice
            # notation into file pointer offset and count
            if start is not None or end is not None:
                if start < 0 and end is None:  # return tail of file
                    start += file_size
                    if start < 0:
                        # if Range:bytes=-1000 in request header but file size
                        # is only 200, there would be trouble without this
                        start = 0
                    count = file_size - start
                else:
                    # rfc7233:If the last-byte-pos value is
                    # absent, or if the value is greater than or equal to
                    # the current length of the representation data,
                    # the byte range is interpreted as the remainder
                    # of the representation (i.e., the server replaces the
                    # value of last-byte-pos with a value that is one less than
                    # the current length of the selected representation).
                    count = min(end if end is not None else file_size,
                                file_size) - start

                if start >= file_size:
                    # HTTP 416 should be returned in this case.
                    #
                    # According to https://tools.ietf.org/html/rfc7233:
                    # If a valid byte-range-set includes at least one
                    # byte-range-spec with a first-byte-pos that is less than
                    # the current length of the representation, or at least one
                    # suffix-byte-range-spec with a non-zero suffix-length,
                    # then the byte-range-set is satisfiable. Otherwise, the
                    # byte-range-set is unsatisfiable.
                    self.headers[hdrs.CONTENT_RANGE] = 'bytes */{0}'.format(
                        file_size)
                    self.set_status(HTTPRequestRangeNotSatisfiable.status_code)
                    return await super().prepare(request)

                status = HTTPPartialContent.status_code
                # Even though you are sending the whole file, you should still
                # return a HTTP 206 for a Range request.

        self.set_status(status)
        if should_set_ct:
            self.content_type = ct
        if encoding:
            self.headers[hdrs.CONTENT_ENCODING] = encoding
        if gzip:
            self.headers[hdrs.VARY] = hdrs.ACCEPT_ENCODING
        self.last_modified = st.st_mtime
        self.content_length = count

        self.headers[hdrs.ACCEPT_RANGES] = 'bytes'

        if status == HTTPPartialContent.status_code:
            self.headers[hdrs.CONTENT_RANGE] = 'bytes {0}-{1}/{2}'.format(
                start, start + count - 1, file_size)

        with filepath.open('rb') as fobj:
            if start:  # be aware that start could be None or int=0 here.
                fobj.seek(start)

            return await self._sendfile(request, fobj, count)
