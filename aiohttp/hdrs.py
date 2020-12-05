"""HTTP Headers constants."""

# After changing the file content call ./tools/gen.py
# to regenerate the headers parser
from typing import Final, Set

from multidict import istr

METH_ANY: Final[str] = "*"
METH_CONNECT: Final[str] = "CONNECT"
METH_HEAD: Final[str] = "HEAD"
METH_GET: Final[str] = "GET"
METH_DELETE: Final[str] = "DELETE"
METH_OPTIONS: Final[str] = "OPTIONS"
METH_PATCH: Final[str] = "PATCH"
METH_POST: Final[str] = "POST"
METH_PUT: Final[str] = "PUT"
METH_TRACE: Final[str] = "TRACE"

METH_ALL: Final[Set[str]] = {
    METH_CONNECT,
    METH_HEAD,
    METH_GET,
    METH_DELETE,
    METH_OPTIONS,
    METH_PATCH,
    METH_POST,
    METH_PUT,
    METH_TRACE,
}

ACCEPT: Final[str] = istr("Accept")
ACCEPT_CHARSET: Final[str] = istr("Accept-Charset")
ACCEPT_ENCODING: Final[str] = istr("Accept-Encoding")
ACCEPT_LANGUAGE: Final[str] = istr("Accept-Language")
ACCEPT_RANGES: Final[str] = istr("Accept-Ranges")
ACCESS_CONTROL_MAX_AGE: Final[str] = istr("Access-Control-Max-Age")
ACCESS_CONTROL_ALLOW_CREDENTIALS: Final[str] = istr("Access-Control-Allow-Credentials")
ACCESS_CONTROL_ALLOW_HEADERS: Final[str] = istr("Access-Control-Allow-Headers")
ACCESS_CONTROL_ALLOW_METHODS: Final[str] = istr("Access-Control-Allow-Methods")
ACCESS_CONTROL_ALLOW_ORIGIN: Final[str] = istr("Access-Control-Allow-Origin")
ACCESS_CONTROL_EXPOSE_HEADERS: Final[str] = istr("Access-Control-Expose-Headers")
ACCESS_CONTROL_REQUEST_HEADERS: Final[str] = istr("Access-Control-Request-Headers")
ACCESS_CONTROL_REQUEST_METHOD: Final[str] = istr("Access-Control-Request-Method")
AGE: Final[str] = istr("Age")
ALLOW: Final[str] = istr("Allow")
AUTHORIZATION: Final[str] = istr("Authorization")
CACHE_CONTROL: Final[str] = istr("Cache-Control")
CONNECTION: Final[str] = istr("Connection")
CONTENT_DISPOSITION: Final[str] = istr("Content-Disposition")
CONTENT_ENCODING: Final[str] = istr("Content-Encoding")
CONTENT_LANGUAGE: Final[str] = istr("Content-Language")
CONTENT_LENGTH: Final[str] = istr("Content-Length")
CONTENT_LOCATION: Final[str] = istr("Content-Location")
CONTENT_MD5: Final[str] = istr("Content-MD5")
CONTENT_RANGE: Final[str] = istr("Content-Range")
CONTENT_TRANSFER_ENCODING: Final[str] = istr("Content-Transfer-Encoding")
CONTENT_TYPE: Final[str] = istr("Content-Type")
COOKIE: Final[str] = istr("Cookie")
DATE: Final[str] = istr("Date")
DESTINATION: Final[str] = istr("Destination")
DIGEST: Final[str] = istr("Digest")
ETAG: Final[str] = istr("Etag")
EXPECT: Final[str] = istr("Expect")
EXPIRES: Final[str] = istr("Expires")
FORWARDED: Final[str] = istr("Forwarded")
FROM: Final[str] = istr("From")
HOST: Final[str] = istr("Host")
IF_MATCH: Final[str] = istr("If-Match")
IF_MODIFIED_SINCE: Final[str] = istr("If-Modified-Since")
IF_NONE_MATCH: Final[str] = istr("If-None-Match")
IF_RANGE: Final[str] = istr("If-Range")
IF_UNMODIFIED_SINCE: Final[str] = istr("If-Unmodified-Since")
KEEP_ALIVE: Final[str] = istr("Keep-Alive")
LAST_EVENT_ID: Final[str] = istr("Last-Event-ID")
LAST_MODIFIED: Final[str] = istr("Last-Modified")
LINK: Final[str] = istr("Link")
LOCATION: Final[str] = istr("Location")
MAX_FORWARDS: Final[str] = istr("Max-Forwards")
ORIGIN: Final[str] = istr("Origin")
PRAGMA: Final[str] = istr("Pragma")
PROXY_AUTHENTICATE: Final[str] = istr("Proxy-Authenticate")
PROXY_AUTHORIZATION: Final[str] = istr("Proxy-Authorization")
RANGE: Final[str] = istr("Range")
REFERER: Final[str] = istr("Referer")
RETRY_AFTER: Final[str] = istr("Retry-After")
SEC_WEBSOCKET_ACCEPT: Final[str] = istr("Sec-WebSocket-Accept")
SEC_WEBSOCKET_VERSION: Final[str] = istr("Sec-WebSocket-Version")
SEC_WEBSOCKET_PROTOCOL: Final[str] = istr("Sec-WebSocket-Protocol")
SEC_WEBSOCKET_EXTENSIONS: Final[str] = istr("Sec-WebSocket-Extensions")
SEC_WEBSOCKET_KEY: Final[str] = istr("Sec-WebSocket-Key")
SEC_WEBSOCKET_KEY1: Final[str] = istr("Sec-WebSocket-Key1")
SERVER: Final[str] = istr("Server")
SET_COOKIE: Final[str] = istr("Set-Cookie")
TE: Final[str] = istr("TE")
TRAILER: Final[str] = istr("Trailer")
TRANSFER_ENCODING: Final[str] = istr("Transfer-Encoding")
UPGRADE: Final[str] = istr("Upgrade")
URI: Final[str] = istr("URI")
USER_AGENT: Final[str] = istr("User-Agent")
VARY: Final[str] = istr("Vary")
VIA: Final[str] = istr("Via")
WANT_DIGEST: Final[str] = istr("Want-Digest")
WARNING: Final[str] = istr("Warning")
WWW_AUTHENTICATE: Final[str] = istr("WWW-Authenticate")
X_FORWARDED_FOR: Final[str] = istr("X-Forwarded-For")
X_FORWARDED_HOST: Final[str] = istr("X-Forwarded-Host")
X_FORWARDED_PROTO: Final[str] = istr("X-Forwarded-Proto")
