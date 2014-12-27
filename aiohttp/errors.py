"""http related errors."""

__all__ = [
    'DisconnectedError', 'ClientDisconnectedError', 'ServerDisconnectedError',

    'HttpProcessingError', 'BadHttpMessage',
    'HttpMethodNotAllowed', 'HttpBadRequest', 'HttpProxyError',
    'BadStatusLine', 'LineTooLong', 'InvalidHeader',

    'ClientError', 'ClientHttpProcessingError', 'ClientConnectionError',
    'ClientOSError', 'ClientTimeoutError', 'ProxyConnectionError',
    'ClientRequestError', 'ClientResponseError']

from asyncio import TimeoutError


class DisconnectedError(Exception):
    """disconnected."""


class ClientDisconnectedError(DisconnectedError):
    """Client disconnected."""


class ServerDisconnectedError(DisconnectedError):
    """Server disconnected."""


class ClientError(Exception):
    """Base class for client connection errors."""


class ClientHttpProcessingError(ClientError):
    """Base class for client http processing errors."""


class ClientRequestError(ClientHttpProcessingError):
    """Connection error during sending request."""


class ClientResponseError(ClientHttpProcessingError):
    """Connection error during reading response."""


class ClientConnectionError(ClientError):
    """Base class for client socket errors."""


class ClientOSError(ClientConnectionError, OSError):
    """OSError error."""


class ClientTimeoutError(ClientConnectionError, TimeoutError):
    """Client connection timeout error."""


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

        super().__init__("%s, message='%s'" % (self.code, message))


class HttpProxyError(HttpProcessingError):
    """Http proxy error.

    Raised in :class:`aiohttp.connector.ProxyConnector` if
    proxy responds with status other than ``200 OK``
    on ``CONNECT`` request.
    """


class BadHttpMessage(HttpProcessingError):

    code = 400
    message = 'Bad Request'

    def __init__(self, message):
        super().__init__(message=message)


class HttpMethodNotAllowed(HttpProcessingError):

    code = 405
    message = 'Method Not Allowed'


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
            "got more than %s bytes when reading %s" % (limit, line))


class InvalidHeader(BadHttpMessage):

    def __init__(self, hdr):
        super().__init__('Invalid HTTP Header: {}'.format(hdr))
        self.hdr = hdr


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
