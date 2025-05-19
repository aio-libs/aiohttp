"""Test digest authentication middleware for aiohttp client."""

from unittest import mock

import pytest
from yarl import URL

from aiohttp import client_exceptions, hdrs
from aiohttp.client_middleware_digest_auth import (
    DigestAuthMiddleware,
    DigestFunctions,
    escape_quotes,
    parse_header_pairs,
    unescape_quotes,
)
from aiohttp.client_reqrep import ClientResponse
from aiohttp.pytest_plugin import AiohttpServer
from aiohttp.web import Application, Request, Response
from aiohttp.web_exceptions import HTTPUnauthorized

# ------------------- DigestAuth Tests -----------------------------------


@pytest.fixture
def digest_auth_mw() -> DigestAuthMiddleware:
    return DigestAuthMiddleware("user", "pass")


async def test_authenticate_valid_digest(digest_auth_mw: DigestAuthMiddleware) -> None:
    response = mock.Mock(spec=ClientResponse)
    response.status = 401
    response.headers = {
        "www-authenticate": 'Digest realm="test", nonce="abc", qop="auth", opaque="xyz", algorithm=MD5'
    }

    assert digest_auth_mw._authenticate(response)
    assert digest_auth_mw.challenge["realm"] == "test"
    assert digest_auth_mw.challenge["nonce"] == "abc"
    assert digest_auth_mw.challenge["qop"] == "auth"
    assert digest_auth_mw.challenge["algorithm"] == "MD5"
    assert digest_auth_mw.challenge["opaque"] == "xyz"


async def test_authenticate_invalid_status(
    digest_auth_mw: DigestAuthMiddleware,
) -> None:
    response = mock.Mock(spec=ClientResponse)
    response.status = 200
    response.headers = {}
    assert not digest_auth_mw._authenticate(response)


async def test_authenticate_already_handled(
    digest_auth_mw: DigestAuthMiddleware,
) -> None:
    response = mock.Mock(spec=ClientResponse)
    response.status = 401
    response.headers = {
        "www-authenticate": 'Digest realm="test", nonce="abc", qop="auth"'
    }
    digest_auth_mw.handled_401 = True
    assert not digest_auth_mw._authenticate(response)


def test_encode_without_challenge(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw.handled_401 = False
    assert digest_auth_mw._encode("GET", URL("http://example.com/resource"), "") == ""


def test_encode_missing_realm_or_nonce(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw.handled_401 = True
    digest_auth_mw.challenge = {"nonce": "abc"}
    with pytest.raises(Exception):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_encode_digest_with_md5(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw.handled_401 = True
    digest_auth_mw.challenge = {
        "realm": "test",
        "nonce": "abc",
        "qop": "auth",
        "algorithm": "MD5",
        "opaque": "xyz",
    }
    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert header.startswith("Digest ")
    assert 'username="user"' in header
    assert 'algorithm="MD5"' in header


def test_encode_digest_with_md5_sess(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw.handled_401 = True
    digest_auth_mw.challenge = {
        "realm": "test",
        "nonce": "abc",
        "qop": "auth",
        "algorithm": "MD5-SESS",
    }
    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert 'algorithm="MD5-SESS"' in header


def test_encode_unsupported_algorithm(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw.handled_401 = True
    digest_auth_mw.challenge = {
        "realm": "test",
        "nonce": "abc",
        "algorithm": "UNSUPPORTED",
    }
    assert digest_auth_mw._encode("GET", URL("http://example.com/resource"), "") == ""


def test_invalid_qop_rejected() -> None:
    auth = DigestAuthMiddleware("u", "p")
    auth.challenge = {
        "realm": "r",
        "nonce": "n",
        "qop": "badvalue",
        "algorithm": "MD5",
    }
    auth.handled_401 = True
    with pytest.raises(client_exceptions.ClientError):
        auth._encode("GET", URL("http://x"), "")


def compute_expected_digest(
    algorithm: str,
    username: str,
    password: str,
    realm: str,
    nonce: str,
    uri: str,
    method: str,
    qop: str,
    nc: str,
    cnonce: str,
    body: str = "",
) -> str:
    hash_fn = DigestFunctions[algorithm]

    def H(x: str) -> str:
        return hash_fn(x.encode()).hexdigest()

    def KD(secret: str, data: str) -> str:
        return H(f"{secret}:{data}")

    A1 = f"{username}:{realm}:{password}"
    HA1 = H(A1)

    if algorithm.upper() == "MD5-SESS":
        HA1 = H(f"{HA1}:{nonce}:{cnonce}")

    A2 = f"{method}:{uri}"
    if "auth-int" in qop:
        entity_hash = H(body)
        A2 = f"{A2}:{entity_hash}"
    HA2 = H(A2)

    if qop:
        response = KD(HA1, f"{nonce}:{nc}:{cnonce}:{qop}:{HA2}")
    else:
        response = KD(HA1, f"{nonce}:{HA2}")

    return response


@pytest.mark.parametrize("qop", ["auth", "auth-int", "auth,auth-int"])
@pytest.mark.parametrize("algorithm", list(DigestFunctions.keys()))
def test_digest_response_exact_match(qop: str, algorithm: str) -> None:
    # Fixed input values
    login = "user"
    password = "pass"
    realm = "example.com"
    nonce = "abc123nonce"
    cnonce = "deadbeefcafebabe"
    nc = 1
    ncvalue = f"{nc+1:08x}"
    method = "GET"
    uri = "/secret"
    body = "this is a body"
    qop = "auth-int" if "auth-int" in qop else "auth"

    # Create the auth object
    auth = DigestAuthMiddleware(login, password)
    auth.challenge = {
        "realm": realm,
        "nonce": nonce,
        "qop": qop,
        "algorithm": algorithm,
    }
    auth.handled_401 = True
    auth.last_nonce = nonce
    auth.nonce_count = nc

    # Patch cnonce manually by replacing the auth.encode() logic
    # We'll monkey-patch hashlib.sha1 to return a fixed cnonce if needed
    import hashlib as real_hashlib

    original_sha1 = real_hashlib.sha1

    class FakeSHA1(mock.Mock):
        def hexdigest(self) -> str:
            return cnonce

    real_hashlib.sha1 = lambda *_: FakeSHA1()

    try:
        header = auth._encode(method, URL(f"http://host{uri}"), body)
    finally:
        real_hashlib.sha1 = original_sha1

    # Get expected digest
    expected = compute_expected_digest(
        algorithm=algorithm,
        username=login,
        password=password,
        realm=realm,
        nonce=nonce,
        uri=uri,
        method=method,
        qop=qop,
        nc=ncvalue,
        cnonce=cnonce,
        body=body,
    )

    # Check that the response digest is exactly correct
    assert f'response="{expected}"' in header


def test_parse_header_pairs_quoted() -> None:
    header = 'realm="example.com", nonce="12345", qop="auth"'
    result = parse_header_pairs(header)
    assert result["realm"] == "example.com"
    assert result["nonce"] == "12345"
    assert result["qop"] == "auth"


def test_parse_header_pairs_unquoted() -> None:
    header = "realm=example.com, nonce=12345, qop=auth"
    result = parse_header_pairs(header)
    assert result["realm"] == "example.com"
    assert result["nonce"] == "12345"
    assert result["qop"] == "auth"


def test_parse_header_mixed() -> None:
    header = 'realm="ex,ample", nonce=12345, qop="auth", domain="/test"'
    result = parse_header_pairs(header)
    assert result["realm"] == "ex,ample"
    assert result["nonce"] == "12345"
    assert result["qop"] == "auth"
    assert result["domain"] == "/test"


def test_digest_auth_middleware_callable() -> None:
    """Test that DigestAuthMiddleware is callable."""
    middleware = DigestAuthMiddleware("user", "pass")
    assert callable(middleware)


def test_middleware_invalid_login() -> None:
    """Test that invalid login values raise errors."""
    with pytest.raises(ValueError, match="None is not allowed as login value"):
        DigestAuthMiddleware(None, "pass")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="None is not allowed as password value"):
        DigestAuthMiddleware("user", None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"A \":\" is not allowed in username"):
        DigestAuthMiddleware("user:name", "pass")


def test_escaping_quotes_in_auth_header() -> None:
    """Test that double quotes are properly escaped in auth header."""
    auth = DigestAuthMiddleware('user"with"quotes', "pass")
    auth.handled_401 = True
    auth.challenge = {
        "realm": 'realm"with"quotes',
        "nonce": 'nonce"with"quotes',
        "qop": "auth",
        "algorithm": "MD5",
        "opaque": 'opaque"with"quotes',
    }

    header = auth._encode("GET", URL("http://example.com/path"), "")

    # Check that quotes are escaped in the header
    assert 'username="user\\"with\\"quotes"' in header
    assert 'realm="realm\\"with\\"quotes"' in header
    assert 'nonce="nonce\\"with\\"quotes"' in header
    assert 'opaque="opaque\\"with\\"quotes"' in header


def test_escape_unescape_quotes_functions() -> None:
    """Test that escape_quotes and unescape_quotes work correctly."""
    # Test basic escaping and unescaping
    original = 'value"with"quotes'
    escaped = escape_quotes(original)
    assert escaped == 'value\\"with\\"quotes'

    # Test unescaping
    unescaped = unescape_quotes(escaped)
    assert unescaped == original

    # Test edge cases
    assert escape_quotes("") == ""
    assert unescape_quotes("") == ""
    assert escape_quotes("no quotes") == "no quotes"
    assert unescape_quotes("no quotes") == "no quotes"

    # Test that they're inverse operations
    test_strings = [
        "simple",
        'with"one"quote',
        'many"quotes"in"string',
        '""',
        '"',
        'already\\"escaped',
    ]

    for s in test_strings:
        assert unescape_quotes(escape_quotes(s)) == s


async def test_middleware_retry_on_401(aiohttp_server: AiohttpServer) -> None:
    """Test that the middleware retries on 401 errors."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge
            raise HTTPUnauthorized(
                headers={
                    "WWW-Authenticate": 'Digest realm="test", nonce="abc123", qop="auth"'
                },
                text="Unauthorized",
            )

        # Second request should have Authorization header
        auth_header = request.headers.get(hdrs.AUTHORIZATION)
        if auth_header and auth_header.startswith("Digest "):
            resp = Response()
            resp.text = "OK"
            return resp

        raise HTTPUnauthorized(text="Still unauthorized")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create a mock session with the middleware
    from aiohttp import ClientSession

    middleware = DigestAuthMiddleware("user", "pass")

    async with ClientSession(middlewares=(middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth
