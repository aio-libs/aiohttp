"""HTTP related errors."""

from asyncio import TimeoutError

__all__ = (
    'ServerDisconnectedError',

    'ClientError', 'ClientConnectionError',
    'ClientOSError', 'ClientTimeoutError', 'ProxyConnectionError',
    'ClientRequestError',

    'ClientResponseError', 'HttpProxyError', 'FingerprintMismatch',
    'WSServerHandshakeError')


class ClientError(Exception):
    """Base class for client connection errors."""


# backward compatibility
ClientDisconnectedError = ClientError


class ServerDisconnectedError(ClientError):
    """Server disconnected."""


class ClientRequestError(ClientError):
    """Connection error during sending request."""


class ClientResponseError(ClientError):
    """Connection error during reading response."""

    code = 0
    message = ''
    headers = None

    def __init__(self, *, code=None, message='', headers=None):
        if code is not None:
            self.code = code
            self.message = message
            self.headers = headers

        super().__init__("%s, message='%s'" % (self.code, message))


class ClientConnectionError(ClientError):
    """Base class for client socket errors."""


class ClientOSError(ClientConnectionError, OSError):
    """OSError error."""


class ClientTimeoutError(ClientConnectionError, TimeoutError):
    """Client connection timeout error."""


class ProxyConnectionError(ClientConnectionError):
    """Proxy connection error.

    Raised in :class:`aiohttp.connector.TCPConnector` if
    connection to proxy can not be established.
    """


class WSServerHandshakeError(ClientResponseError):
    """websocket server handshake error."""


class HttpProxyError(ClientResponseError):
    """HTTP proxy error.

    Raised in :class:`aiohttp.connector.TCPConnector` if
    proxy responds with status other than ``200 OK``
    on ``CONNECT`` request.
    """


class FingerprintMismatch(ClientConnectionError):
    """SSL certificate does not match expected fingerprint."""

    def __init__(self, expected, got, host, port):
        self.expected = expected
        self.got = got
        self.host = host
        self.port = port

    def __repr__(self):
        return '<{} expected={} got={} host={} port={}>'.format(
            self.__class__.__name__, self.expected, self.got,
            self.host, self.port)
