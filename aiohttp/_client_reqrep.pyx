cdef class ConnectionKey:

    cdef readonly str host
    cdef readonly object port
    cdef readonly bint is_ssl
    cdef readonly object ssl
    cdef readonly object proxy
    cdef readonly object proxy_auth
    cdef readonly object proxy_headers_hash
    cdef readonly Py_hash_t _hash

    def __init__(self, host, port, is_ssl, ssl, proxy, proxy_auth, proxy_headers_hash):
        self.host = host
        self.port = port
        self.is_ssl = is_ssl
        self.ssl = ssl
        self.proxy = proxy
        self.proxy_auth = proxy_auth
        self.proxy_headers_hash = proxy_headers_hash
        self._hash = hash((host, port, is_ssl, ssl, proxy, proxy_auth, proxy_headers_hash))

    def __hash__(self):
        return self._hash

    def __eq__(self, other: ConnectionKey):
        if not isinstance(other, ConnectionKey):
            return NotImplemented
        return (
            self.host == other.host and
            self.port == other.port and
            self.is_ssl == other.is_ssl and
            self.ssl == other.ssl and
            self.proxy == other.proxy and
            self.proxy_auth == other.proxy_auth and
            self.proxy_headers_hash == other.proxy_headers_hash
        )
