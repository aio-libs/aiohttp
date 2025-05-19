"""Digest authentication middleware for aiohttp client."""

import hashlib
import os
import re
import time
from contextvars import ContextVar
from typing import Any, Callable, Dict, Final, Optional, TypedDict

from . import client_exceptions, hdrs
from .client_middlewares import ClientHandlerType
from .client_reqrep import ClientRequest, ClientResponse
from .typedefs import URL


class DigestAuthChallenge(TypedDict, total=False):
    realm: str
    nonce: str
    qop: str
    algorithm: str
    opaque: str
    ...


class DigestAuthContext:
    """Context storage for DigestAuth"""

    def __init__(self) -> None:
        self.last_nonce = ""
        self.nonce_count = 0
        self.challenge: DigestAuthChallenge = {}
        self.handled_401 = False


# Context variable for storing DigestAuth context
_digest_context: ContextVar[Optional[DigestAuthContext]] = ContextVar(
    "_digest_context", default=None
)


DigestFunctions: Dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "MD5": hashlib.md5,
    "MD5-SESS": hashlib.md5,
    "SHA": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


# Compile the regex pattern once at module level for performance
_HEADER_PAIRS_PATTERN = re.compile(
    r'(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))'
    # |    |  | | |  |    |      |    |  ||     |
    # +----|--|-|-|--|----|------|----|--||-----|--> alphanumeric key
    #      +--|-|-|--|----|------|----|--||-----|--> maybe whitespace
    #         | | |  |    |      |    |  ||     |
    #         +-|-|--|----|------|----|--||-----|--> = (delimiter)
    #           +-|--|----|------|----|--||-----|--> maybe whitespace
    #             |  |    |      |    |  ||     |
    #             +--|----|------|----|--||-----|--> group quoted or unquoted
    #                |    |      |    |  ||     |
    #                +----|------|----|--||-----|--> if quoted...
    #                     +------|----|--||-----|--> anything but " or \
    #                            +----|--||-----|--> escaped characters allowed
    #                                 +--||-----|--> or can be empty string
    #                                    ||     |
    #                                    +|-----|--> if unquoted...
    #                                     +-----|--> anything but , or <space>
    #                                           +--> at least one char req'd
)


def parse_header_pairs(header: str) -> Dict[str, str]:
    """Parses header pairs in the www-authenticate header value"""
    # RFC 7616 accepts header key/values that look like
    #   key1="value1", key2=value2, key3="some value, with, commas"
    #
    # This regex attempts to parse that out

    return {
        key: (
            (quoted_val or unquoted_val).replace('\\"', '"')
            if quoted_val or unquoted_val
            else ""
        )
        for key, quoted_val, unquoted_val in _HEADER_PAIRS_PATTERN.findall(header)
    }


class DigestAuthMiddleware:
    """
    HTTP digest authentication middleware.

    The work here is based off of
    https://github.com/requests/requests/blob/v2.18.4/requests/auth.py.

    Please also refer to:
    - RFC 7616: HTTP Digest Access Authentication
    - RFC 2617: HTTP Authentication (deprecated by RFC 7616)
    - RFC 1945: Section 11.1 (username restrictions)
    """

    def __init__(
        self,
        login: str,
        password: str,
    ) -> None:
        if login is None:
            raise ValueError("None is not allowed as login value")

        if password is None:
            raise ValueError("None is not allowed as password value")

        if ":" in login:
            raise ValueError('A ":" is not allowed in username (RFC 1945#section-11.1)')

        self.login: Final = login
        self.password: Final = password

    def _get_context(self) -> DigestAuthContext:
        """Get or create the context for this middleware instance."""
        ctx = _digest_context.get()
        if ctx is None:
            ctx = DigestAuthContext()
            _digest_context.set(ctx)
        return ctx

    def _encode(self, method: str, url: URL, body: Any) -> str:
        """Build digest header"""
        ctx = self._get_context()

        if not ctx.handled_401:
            return ""

        if "realm" not in ctx.challenge:
            raise client_exceptions.ClientError("Challenge is missing realm")

        if "nonce" not in ctx.challenge:
            raise client_exceptions.ClientError("Challenge is missing nonce")

        realm: str = ctx.challenge.get("realm", "")
        nonce: str = ctx.challenge.get("nonce", "")
        qop_raw: str = ctx.challenge.get("qop", "")
        algorithm: str = ctx.challenge.get("algorithm", "MD5").upper()
        opaque: str = ctx.challenge.get("opaque", "")

        qop: str = ""
        if qop_raw:
            qop_list = [q.strip() for q in qop_raw.split(",") if q.strip()]
            valid_qops = {"auth", "auth-int"}.intersection(qop_list)
            if not valid_qops:
                raise client_exceptions.ClientError(
                    f"Unsupported qop value(s): {qop_raw}"
                )

            qop = "auth-int" if "auth-int" in valid_qops else "auth"

        if algorithm not in DigestFunctions:
            return ""
        hash_fn: Final = DigestFunctions[algorithm]

        def H(x: str) -> str:
            """RFC 7616 Section 3: Hash function H(data) = hex(hash(data))."""
            return hash_fn(x.encode()).hexdigest()

        def KD(s: str, d: str) -> str:
            """RFC 7616 Section 3: KD(secret, data) = H(concat(secret, ":", data))."""
            return H(f"{s}:{d}")

        path = URL(url).path_qs
        A1 = f"{self.login}:{realm}:{self.password}"
        A2 = f"{method.upper()}:{path}"
        if qop == "auth-int":
            if isinstance(body, bytes):
                entity_str = body.decode("utf-8", errors="replace")
            elif isinstance(body, str):
                entity_str = body
            else:
                entity_str = ""
            entity_hash = H(entity_str)
            A2 = f"{A2}:{entity_hash}"

        HA1 = H(A1)
        HA2 = H(A2)

        if nonce == ctx.last_nonce:
            ctx.nonce_count += 1
        else:
            ctx.nonce_count = 1

        ctx.last_nonce = nonce

        ncvalue = f"{ctx.nonce_count:08x}"

        # cnonce is just a random string generated by the client.
        cnonce_data = "".join(
            [
                str(ctx.nonce_count),
                nonce,
                time.ctime(),
                os.urandom(8).decode(errors="ignore"),
            ]
        ).encode()
        cnonce = hashlib.sha1(cnonce_data).hexdigest()[:16]

        if algorithm == "MD5-SESS":
            HA1 = H(f"{HA1}:{nonce}:{cnonce}")

        if qop:
            noncebit = ":".join([nonce, ncvalue, cnonce, qop, HA2])
            response_digest = KD(HA1, noncebit)
        else:
            response_digest = KD(HA1, f"{nonce}:{HA2}")

        # Note: All values are already properly escaped/validated:
        # - self.login: validated to not contain ":" in __init__
        # - realm, nonce, opaque: server-provided values
        # - path: URL-encoded path component
        # - response_digest: hex-encoded hash output
        # - algorithm: matched against whitelist in DigestFunctions
        pairs = [
            f'username="{self.login}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{path}"',
            f'response="{response_digest}"',
            f'algorithm="{algorithm}"',
        ]
        if opaque:
            pairs.append(f'opaque="{opaque}"')
        if qop:
            pairs.append(f'qop="{qop}"')
            pairs.append(f"nc={ncvalue}")
            pairs.append(f'cnonce="{cnonce}"')

        ctx.handled_401 = False

        return f"Digest {', '.join(pairs)}"

    def _authenticate(self, response: ClientResponse) -> bool:
        """
        Takes the given response and tries digest-auth, if needed.

        Returns true if the original request must be resent.
        """
        ctx = self._get_context()

        # Effective recursion guard
        if ctx.handled_401:
            return False

        if response.status != 401:
            ctx.handled_401 = False
            return False

        auth_header = response.headers.get("www-authenticate", "")

        parts = auth_header.split(" ", 1)
        if "digest" == parts[0].lower() and len(parts) > 1 and not ctx.handled_401:
            ctx.handled_401 = True

            header_pairs = parse_header_pairs(parts[1])

            # RFC 7616: Extract challenge parameters
            challenge_fields = ("realm", "nonce", "qop", "algorithm", "opaque")
            ctx.challenge = {}
            for field in challenge_fields:
                if field in header_pairs and header_pairs[field]:
                    ctx.challenge[field] = header_pairs[field]

            return True

        return False

    async def __call__(
        self, request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        """Run the digest auth middleware."""
        retry_count = 0

        while True:
            ctx = self._get_context()

            # For the first request, make sure context is clean
            if retry_count == 0:
                ctx.handled_401 = False

            # Apply authorization header if we have a challenge
            auth_header = self._encode(request.method, request.url, request.body)
            if auth_header:
                request.headers[hdrs.AUTHORIZATION] = auth_header

            # Send the request
            response = await handler(request)

            # Check if we need to authenticate
            if self._authenticate(response) and retry_count < 1:
                retry_count += 1
                response.close()
                continue  # Retry the request with digest auth

            return response


# Example usage:
# >>> auth = DigestAuthMiddleware("user", "pass")
# >>> async with ClientSession(middlewares=(auth,)) as session:
# ...     async with session.get("http://example.com") as resp:
# ...         assert resp.status == 200
