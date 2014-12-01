"""http related errors."""

__all__ = ['HttpProcessingError', 'BadHttpMessage',
           'HttpMethodNotAllowed', 'HttpBadRequest',
           'IncompleteRead', 'BadStatusLine', 'LineTooLong', 'InvalidHeader',
           'HttpProxyError',

           'ClientConnectionError', 'OsConnectionError',
           'ClientRequestError', 'ClientResponseError',
           'TimeoutError', 'ProxyConnectionError']

from asyncio import TimeoutError


class ClientConnectionError(Exception):
    """Base class for client connection errors."""


class ClientRequestError(ClientConnectionError):
    """Connection error during sending request."""


class ClientResponseError(ClientConnectionError):
    """Connection error during reading response."""


class OsConnectionError(ClientConnectionError):
    """OSError error."""


class ProxyConnectionError(ClientConnectionError):
    """Proxy connection error.

    Raised in :class:`aiohttp.connector.ProxyConnector` if
    connection to proxy can not be established.
    """


class HttpProcessingError(Exception):
    """Http error.

    Shortcut for raising http errors with custom code, message and headers.

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

        super().__init__("%s, message='%s'" % (code, message))


class HttpProxyError(HttpProcessingError):
    """Http proxy error.

    Raised in :class:`aiohttp.connector.ProxyConnector` if
    proxy responds with status other than ``200 OK``
    on ``CONNECT`` request.
    """


class BadHttpMessage(HttpProcessingError):

    code = 400
    message = 'Bad Request'


class HttpMethodNotAllowed(HttpProcessingError):

    code = 405
    message = 'Method Not Allowed'


class HttpBadRequest(BadHttpMessage):

    code = 400
    message = 'Bad Request'


class LineTooLong(BadHttpMessage):

    def __init__(self, line, limit='Unknown'):
        super().__init__(
            message="got more than %s bytes when reading %s" % (limit, line))


class InvalidHeader(BadHttpMessage):

    def __init__(self, hdr):
        super().__init__(message='Invalid HTTP Header: {}'.format(hdr))
        self.hdr = hdr


class IncompleteRead(BadHttpMessage):

    def __init__(self, partial, expected=None):
        self.args = partial,
        self.partial = partial
        self.expected = expected

    def __repr__(self):
        if self.expected is not None:
            e = ', %i more expected' % self.expected
        else:
            e = ''
        return 'IncompleteRead(%i bytes read%s)' % (self.partial, e)

    def __str__(self):
        return repr(self)


class BadStatusLine(BadHttpMessage):

    def __init__(self, line=''):
        if not line:
            line = repr(line)
        self.args = line,
        self.line = line


class ParserError(Exception):
    """Base parser error."""


class LineLimitExceededParserError(ParserError):
    """Line is too long."""

    def __init__(self, msg, limit):
        super().__init__(msg)
        self.limit = limit
