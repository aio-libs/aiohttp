"""Low-level http related exceptions."""

__all__ = ('HttpProcessingError',)


class HttpProcessingError(Exception):
    """HTTP error.

    Shortcut for raising HTTP errors with custom code, message and headers.

    :param int code: HTTP Error code.
    :param str message: (optional) Error message.
    :param list of [tuple] headers: (optional) Headers to be sent in response.
    """

    code = 0
    message = ''
    headers = None

    def __init__(self, *, code=None, message='', headers=None):
        if code is not None:
            self.code = code
        self.headers = headers
        self.message = message

        super().__init__("%s, message='%s'" % (self.code, message))


class BadHttpMessage(HttpProcessingError):

    code = 400
    message = 'Bad Request'

    def __init__(self, message, *, headers=None):
        super().__init__(message=message, headers=headers)


class HttpBadRequest(BadHttpMessage):

    code = 400
    message = 'Bad Request'


class ContentEncodingError(BadHttpMessage):
    """Content encoding error."""


class TransferEncodingError(BadHttpMessage):
    """transfer encoding error."""


class LineTooLong(BadHttpMessage):

    def __init__(self, line, limit='Unknown'):
        super().__init__(
            "Got more than %s bytes when reading %s." % (limit, line))


class InvalidHeader(BadHttpMessage):

    def __init__(self, hdr):
        if isinstance(hdr, bytes):
            hdr = hdr.decode('utf-8', 'surrogateescape')
        super().__init__('Invalid HTTP Header: {}'.format(hdr))
        self.hdr = hdr


class BadStatusLine(BadHttpMessage):

    def __init__(self, line=''):
        if not line:
            line = repr(line)
        self.args = line,
        self.line = line


class InvalidURLError(BadHttpMessage):
    pass
