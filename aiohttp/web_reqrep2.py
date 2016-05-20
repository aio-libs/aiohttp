"""HTTP/2 equivalent of web_reqrep.py"""

import aiohttp.web_reqrep

from aiohttp.protocol2 import Http2Response as ResponseImpl


class Http2Response(aiohttp.web_reqrep.Response):
    """
    Overrides the basic response object to ensure that HTTP/2 is used.
    """
    def _start(self, request):
        self._req = request
        keep_alive = self._keep_alive
        if keep_alive is None:
            keep_alive = request.keep_alive
        self._keep_alive = keep_alive

        resp_impl = self._resp_impl = ResponseImpl(
            request._h2_conn,
            request._writer,
            self._status,
            request._h2_stream_id)

        self._copy_cookies()

        if self._compression:
            self._start_compression(request)

        assert not self._chunked, "Chunked not supported in HTTP/2"

        headers = self.headers.items()
        for key, val in headers:
            resp_impl.add_header(key, val)

        resp_impl.send_headers()
        return resp_impl
