"""http related errors."""

__all__ = ['HttpException', 'HttpErrorException',
           'HttpBadRequest', 'HttpMethodNotAllowed',
           'IncompleteRead', 'BadStatusLine', 'LineTooLong', 'InvalidHeader',
           'ConnectionError', 'OsConnectionError', 'ClientConnectionError',
           'TimeoutError', 'ProxyConnectionError', 'HttpProxyError']

from asyncio import TimeoutError


class ConnectionError(Exception):
    """http connection error."""


class OsConnectionError(ConnectionError):
    """OSError error."""


class ClientConnectionError(ConnectionError):
    """BadStatusLine error."""  # ???


class ProxyConnectionError(ClientConnectionError):
    """Proxy connection error.

    Raised in :class:`aiohttp.connector.ProxyConnector` if
    connection to proxy can not be established.
    """


class HttpException(Exception):
    """Base http exception class."""

    code = None
    headers = ()
    message = ''


class HttpErrorException(HttpException):
    """Http error.

    Shortcut for raising http errors with custom code, message and headers.

    :param int code: HTTP Error code.
    :param str message: (optional) Error message.
    :param list of [tuple] headers: (optional) Headers to be sent in response.
    """

    def __init__(self, code, message='', headers=None):
        self.code = code
        self.headers = headers
        self.message = message


class HttpProxyError(HttpErrorException):
    """Http proxy error.

    Raised in :class:`aiohttp.connector.ProxyConnector` if
    proxy responds with status other than ``200 OK``
    on ``CONNECT`` request.
    """


class HttpBadRequest(HttpException):

    code = 400
    message = 'Bad Request'


class HttpMethodNotAllowed(HttpException):

    code = 405
    message = 'Method Not Allowed'


class LineTooLong(HttpBadRequest):

    def __init__(self, line, limit='Unknown'):
        super().__init__(
            "got more than %s bytes when reading %s" % (limit, line))


class InvalidHeader(HttpBadRequest):

    def __init__(self, hdr):
        super().__init__('Invalid HTTP Header: {}'.format(hdr))
        self.hdr = hdr


class IncompleteRead(ConnectionError):

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


class BadStatusLine(HttpBadRequest):

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
