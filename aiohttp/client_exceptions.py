"""HTTP related errors."""

from asyncio import TimeoutError

__all__ = (
    'ClientError', 'ClientRequestError',

    'ClientConnectionError',
    'ClientOSError', 'ClientConnectorError', 'ClientProxyConnectionError',

    'ServerConnectionError', 'ServerTimeoutError', 'ServerDisconnectedError',
    'ServerFingerprintMismatch',

    'ClientResponseError', 'ClientHttpProxyError', 'WSServerHandshakeError')


class ClientError(Exception):
    """Base class for client connection errors."""


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


class WSServerHandshakeError(ClientResponseError):
    """websocket server handshake error."""


class ClientHttpProxyError(ClientResponseError):
    """HTTP proxy error.

    Raised in :class:`aiohttp.connector.TCPConnector` if
    proxy responds with status other than ``200 OK``
    on ``CONNECT`` request.
    """


class ClientConnectionError(ClientError):
    """Base class for client socket errors."""


class ClientOSError(ClientConnectionError, OSError):
    """OSError error."""


class ClientConnectorError(ClientOSError):
    """Client connector error.

    Raised in :class:`aiohttp.connector.TCPConnector` if
        connection to proxy can not be established.
    """


class ClientProxyConnectionError(ClientConnectorError):
    """Proxy connection error.

    Raised in :class:`aiohttp.connector.TCPConnector` if
        connection to proxy can not be established.
    """


class ServerConnectionError(ClientConnectionError):
    """Server connection errors."""


class ServerDisconnectedError(ServerConnectionError):
    """Server disconnected."""


class ServerTimeoutError(ServerConnectionError, TimeoutError):
    """Server timeout error."""


class ServerFingerprintMismatch(ServerConnectionError):
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


# backward compatibility
ClientDisconnectedError = ClientError
ClientTimeoutError = ServerTimeoutError
FingerprintMismatch = ServerFingerprintMismatch
HttpProxyError = ClientHttpProxyError
ProxyConnectionError = ClientProxyConnectionError
