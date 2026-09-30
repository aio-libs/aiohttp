"""HTTP Headers constants."""

# After changing the file content call ./tools/gen.py
# to regenerate the headers parser
import itertools
from typing import Final

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

METH_ALL: Final[set[str]] = {
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

# Defined by IETF RFCs
ACCEPT: Final[istr] = istr("Accept")
ACCEPT_CHARSET: Final[istr] = istr("Accept-Charset")
ACCEPT_ENCODING: Final[istr] = istr("Accept-Encoding")
ACCEPT_LANGUAGE: Final[istr] = istr("Accept-Language")
ACCEPT_RANGES: Final[istr] = istr("Accept-Ranges")
AGE: Final[istr] = istr("Age")
ALLOW: Final[istr] = istr("Allow")
ALT_SVC: Final[istr] = istr("Alt-Svc")
ALT_USED: Final[istr] = istr("Alt-Used")
AUTHENTICATION_INFO: Final[istr] = istr("Authentication-Info")
AUTHORIZATION: Final[istr] = istr("Authorization")
CACHE_CONTROL: Final[istr] = istr("Cache-Control")
CACHE_STATUS: Final[istr] = istr("Cache-Status")
CDN_CACHE_CONTROL: Final[istr] = istr("CDN-Cache-Control")
CDN_LOOP: Final[istr] = istr("CDN-Loop")
CONNECTION: Final[istr] = istr("Connection")
CONTENT_DIGEST: Final[istr] = istr("Content-Digest")
CONTENT_DISPOSITION: Final[istr] = istr("Content-Disposition")
CONTENT_ENCODING: Final[istr] = istr("Content-Encoding")
CONTENT_ID: Final[istr] = istr("Content-ID")
CONTENT_LANGUAGE: Final[istr] = istr("Content-Language")
CONTENT_LENGTH: Final[istr] = istr("Content-Length")
CONTENT_LOCATION: Final[istr] = istr("Content-Location")
CONTENT_MD5: Final[istr] = istr("Content-MD5")
CONTENT_RANGE: Final[istr] = istr("Content-Range")
CONTENT_TRANSFER_ENCODING: Final[istr] = istr("Content-Transfer-Encoding")
CONTENT_TYPE: Final[istr] = istr("Content-Type")
COOKIE: Final[istr] = istr("Cookie")
DATE: Final[istr] = istr("Date")
DESTINATION: Final[istr] = istr("Destination")
DIGEST: Final[istr] = istr("Digest")
EARLY_DATA: Final[istr] = istr("Early-Data")
ETAG: Final[istr] = istr("Etag")
EXPECT: Final[istr] = istr("Expect")
EXPIRES: Final[istr] = istr("Expires")
FORWARDED: Final[istr] = istr("Forwarded")
FROM: Final[istr] = istr("From")
HOST: Final[istr] = istr("Host")
IF_MATCH: Final[istr] = istr("If-Match")
IF_MODIFIED_SINCE: Final[istr] = istr("If-Modified-Since")
IF_NONE_MATCH: Final[istr] = istr("If-None-Match")
IF_RANGE: Final[istr] = istr("If-Range")
IF_UNMODIFIED_SINCE: Final[istr] = istr("If-Unmodified-Since")
KEEP_ALIVE: Final[istr] = istr("Keep-Alive")
LAST_MODIFIED: Final[istr] = istr("Last-Modified")
LINK: Final[istr] = istr("Link")
LOCATION: Final[istr] = istr("Location")
MAX_FORWARDS: Final[istr] = istr("Max-Forwards")
ORIGIN: Final[istr] = istr("Origin")
PRAGMA: Final[istr] = istr("Pragma")
PRIORITY: Final[istr] = istr("Priority")
PROXY_AUTHENTICATE: Final[istr] = istr("Proxy-Authenticate")
PROXY_AUTHENTICATION_INFO: Final[istr] = istr("Proxy-Authentication-Info")
PROXY_AUTHORIZATION: Final[istr] = istr("Proxy-Authorization")
RANGE: Final[istr] = istr("Range")
REFERER: Final[istr] = istr("Referer")
REPR_DIGEST: Final[istr] = istr("Repr-Digest")
RETRY_AFTER: Final[istr] = istr("Retry-After")
SEC_WEBSOCKET_ACCEPT: Final[istr] = istr("Sec-WebSocket-Accept")
SEC_WEBSOCKET_EXTENSIONS: Final[istr] = istr("Sec-WebSocket-Extensions")
SEC_WEBSOCKET_KEY: Final[istr] = istr("Sec-WebSocket-Key")
SEC_WEBSOCKET_KEY1: Final[istr] = istr("Sec-WebSocket-Key1")  # hixie-76 draft
SEC_WEBSOCKET_PROTOCOL: Final[istr] = istr("Sec-WebSocket-Protocol")
SEC_WEBSOCKET_VERSION: Final[istr] = istr("Sec-WebSocket-Version")
SERVER: Final[istr] = istr("Server")
SET_COOKIE: Final[istr] = istr("Set-Cookie")
STRICT_TRANSPORT_SECURITY: Final[istr] = istr("Strict-Transport-Security")
TE: Final[istr] = istr("TE")
TRAILER: Final[istr] = istr("Trailer")
TRANSFER_ENCODING: Final[istr] = istr("Transfer-Encoding")
UPGRADE: Final[istr] = istr("Upgrade")
URI: Final[istr] = istr("URI")
USER_AGENT: Final[istr] = istr("User-Agent")
VARY: Final[istr] = istr("Vary")
VIA: Final[istr] = istr("Via")
WANT_CONTENT_DIGEST: Final[istr] = istr("Want-Content-Digest")
WANT_DIGEST: Final[istr] = istr("Want-Digest")
WANT_REPR_DIGEST: Final[istr] = istr("Want-Repr-Digest")
WARNING: Final[istr] = istr("Warning")
WWW_AUTHENTICATE: Final[istr] = istr("WWW-Authenticate")

# Web platform specs (W3C, WHATWG, WICG); sent and read by browsers
ACCEPT_CH: Final[istr] = istr("Accept-CH")
ACCESS_CONTROL_ALLOW_CREDENTIALS: Final[istr] = istr("Access-Control-Allow-Credentials")
ACCESS_CONTROL_ALLOW_HEADERS: Final[istr] = istr("Access-Control-Allow-Headers")
ACCESS_CONTROL_ALLOW_METHODS: Final[istr] = istr("Access-Control-Allow-Methods")
ACCESS_CONTROL_ALLOW_ORIGIN: Final[istr] = istr("Access-Control-Allow-Origin")
ACCESS_CONTROL_EXPOSE_HEADERS: Final[istr] = istr("Access-Control-Expose-Headers")
ACCESS_CONTROL_MAX_AGE: Final[istr] = istr("Access-Control-Max-Age")
ACCESS_CONTROL_REQUEST_HEADERS: Final[istr] = istr("Access-Control-Request-Headers")
ACCESS_CONTROL_REQUEST_METHOD: Final[istr] = istr("Access-Control-Request-Method")
BAGGAGE: Final[istr] = istr("baggage")
CLEAR_SITE_DATA: Final[istr] = istr("Clear-Site-Data")
CONTENT_SECURITY_POLICY: Final[istr] = istr("Content-Security-Policy")
CONTENT_SECURITY_POLICY_REPORT_ONLY: Final[istr] = istr(
    "Content-Security-Policy-Report-Only"
)
CROSS_ORIGIN_EMBEDDER_POLICY: Final[istr] = istr("Cross-Origin-Embedder-Policy")
CROSS_ORIGIN_OPENER_POLICY: Final[istr] = istr("Cross-Origin-Opener-Policy")
CROSS_ORIGIN_RESOURCE_POLICY: Final[istr] = istr("Cross-Origin-Resource-Policy")
LAST_EVENT_ID: Final[istr] = istr("Last-Event-ID")
NEL: Final[istr] = istr("NEL")
ORIGIN_AGENT_CLUSTER: Final[istr] = istr("Origin-Agent-Cluster")
PERMISSIONS_POLICY: Final[istr] = istr("Permissions-Policy")
REFERRER_POLICY: Final[istr] = istr("Referrer-Policy")
REPORTING_ENDPOINTS: Final[istr] = istr("Reporting-Endpoints")
REPORT_TO: Final[istr] = istr("Report-To")
SEC_CH_UA: Final[istr] = istr("Sec-CH-UA")
SEC_CH_UA_MOBILE: Final[istr] = istr("Sec-CH-UA-Mobile")
SEC_CH_UA_PLATFORM: Final[istr] = istr("Sec-CH-UA-Platform")
SEC_FETCH_DEST: Final[istr] = istr("Sec-Fetch-Dest")
SEC_FETCH_MODE: Final[istr] = istr("Sec-Fetch-Mode")
SEC_FETCH_SITE: Final[istr] = istr("Sec-Fetch-Site")
SEC_FETCH_USER: Final[istr] = istr("Sec-Fetch-User")
SEC_GPC: Final[istr] = istr("Sec-GPC")
SEC_PURPOSE: Final[istr] = istr("Sec-Purpose")
SERVER_TIMING: Final[istr] = istr("Server-Timing")
TIMING_ALLOW_ORIGIN: Final[istr] = istr("Timing-Allow-Origin")
TRACEPARENT: Final[istr] = istr("traceparent")
TRACESTATE: Final[istr] = istr("tracestate")
UPGRADE_INSECURE_REQUESTS: Final[istr] = istr("Upgrade-Insecure-Requests")
X_CONTENT_TYPE_OPTIONS: Final[istr] = istr("X-Content-Type-Options")
X_FRAME_OPTIONS: Final[istr] = istr("X-Frame-Options")

# De facto; added by reverse proxies and load balancers
X_FORWARDED_FOR: Final[istr] = istr("X-Forwarded-For")
X_FORWARDED_HOST: Final[istr] = istr("X-Forwarded-Host")
X_FORWARDED_PORT: Final[istr] = istr("X-Forwarded-Port")
X_FORWARDED_PROTO: Final[istr] = istr("X-Forwarded-Proto")
X_REAL_IP: Final[istr] = istr("X-Real-IP")
X_REQUEST_ID: Final[istr] = istr("X-Request-ID")

# De facto; set by applications and frameworks
X_CORRELATION_ID: Final[istr] = istr("X-Correlation-ID")
X_POWERED_BY: Final[istr] = istr("X-Powered-By")
X_RATELIMIT_LIMIT: Final[istr] = istr("X-RateLimit-Limit")
X_RATELIMIT_REMAINING: Final[istr] = istr("X-RateLimit-Remaining")
X_RATELIMIT_RESET: Final[istr] = istr("X-RateLimit-Reset")
X_REQUESTED_WITH: Final[istr] = istr("X-Requested-With")
X_XSS_PROTECTION: Final[istr] = istr("X-XSS-Protection")

# Case permutations of the Host header — for callers that match against
# raw header tokens before istr/CIMultiDict folding.
HOST_ALL: Final = frozenset(
    map("".join, itertools.product(*zip(HOST.upper(), HOST.lower())))
)
