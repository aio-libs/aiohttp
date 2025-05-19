"""Test digest authentication middleware for aiohttp client."""

from unittest import mock

import pytest
from yarl import URL

from aiohttp import hdrs
from aiohttp.client_exceptions import ClientError
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
    assert digest_auth_mw._challenge["realm"] == "test"
    assert digest_auth_mw._challenge["nonce"] == "abc"
    assert digest_auth_mw._challenge["qop"] == "auth"
    assert digest_auth_mw._challenge["algorithm"] == "MD5"
    assert digest_auth_mw._challenge["opaque"] == "xyz"


async def test_authenticate_invalid_status(
    digest_auth_mw: DigestAuthMiddleware,
) -> None:
    response = mock.Mock(spec=ClientResponse)
    response.status = 200
    response.headers = {}
    assert not digest_auth_mw._authenticate(response)


async def test_authenticate_multiple_attempts(
    digest_auth_mw: DigestAuthMiddleware,
) -> None:
    response = mock.Mock(spec=ClientResponse)
    response.status = 401
    response.headers = {
        "www-authenticate": 'Digest realm="test", nonce="abc", qop="auth"'
    }
    # Without the _handled_401 flag, authenticate always returns True for valid 401s
    # The retry prevention is now handled by retry_count in __call__ method
    assert digest_auth_mw._authenticate(response)


def test_encode_without_challenge(digest_auth_mw: DigestAuthMiddleware) -> None:
    # With no challenge set, _encode should raise an error about missing realm
    with pytest.raises(
        ClientError, match="Malformed Digest auth challenge: Missing 'realm' parameter"
    ):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_encode_missing_realm_or_nonce(digest_auth_mw: DigestAuthMiddleware) -> None:
    # Test with missing realm
    digest_auth_mw._challenge = {"nonce": "abc"}
    with pytest.raises(ClientError, match="Missing 'realm' parameter"):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")

    # Test with missing nonce
    digest_auth_mw._challenge = {"realm": "test"}
    with pytest.raises(ClientError, match="Missing 'nonce' parameter"):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")

    # Test with empty nonce
    digest_auth_mw._challenge = {"realm": "test", "nonce": ""}
    with pytest.raises(ClientError, match="empty 'nonce' value"):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_encode_digest_with_md5(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw._challenge = {
        "realm": "test",
        "nonce": "abc",
        "qop": "auth",
        "algorithm": "MD5",
        "opaque": "xyz",
    }
    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert header.startswith("Digest ")
    assert 'username="user"' in header
    assert "algorithm=MD5" in header


def test_encode_digest_with_md5_sess(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw._challenge = {
        "realm": "test",
        "nonce": "abc",
        "qop": "auth",
        "algorithm": "MD5-SESS",
    }
    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert "algorithm=MD5-SESS" in header


def test_encode_unsupported_algorithm(digest_auth_mw: DigestAuthMiddleware) -> None:
    """Test that unsupported algorithm raises ClientError."""
    digest_auth_mw._challenge = {
        "realm": "test",
        "nonce": "abc",
        "algorithm": "UNSUPPORTED",
    }
    with pytest.raises(ClientError, match="Unsupported hash algorithm"):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_invalid_qop_rejected() -> None:
    """Test that invalid Quality of Protection values are rejected."""
    auth = DigestAuthMiddleware("u", "p")
    auth._challenge = {
        "realm": "r",
        "nonce": "n",
        "qop": "badvalue",
        "algorithm": "MD5",
    }
    with pytest.raises(ClientError, match="Unsupported Quality of Protection"):
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
    auth._challenge = {
        "realm": realm,
        "nonce": nonce,
        "qop": qop,
        "algorithm": algorithm,
    }
    auth._last_nonce_bytes = nonce.encode("utf-8")
    auth._nonce_count = nc

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


def test_parse_header_with_scheme() -> None:
    """Test parsing header that includes the scheme."""
    header = 'Digest realm="example.com", nonce="12345", qop="auth"'
    result = parse_header_pairs(header)
    assert result["realm"] == "example.com"
    assert result["nonce"] == "12345"
    assert result["qop"] == "auth"


def test_parse_header_edge_cases() -> None:
    """Test various edge cases for header parsing."""
    # Empty header
    assert parse_header_pairs("") == {}

    # No space after comma
    header = 'realm="test",nonce="123",qop="auth"'
    result = parse_header_pairs(header)
    assert result["realm"] == "test"
    assert result["nonce"] == "123"
    assert result["qop"] == "auth"

    # Extra spaces
    header = 'realm  =  "test"  ,  nonce  =  "123"'
    result = parse_header_pairs(header)
    assert result["realm"] == "test"
    assert result["nonce"] == "123"

    # Escaped quotes
    header = 'realm="test\\"realm", nonce="123"'
    result = parse_header_pairs(header)
    assert result["realm"] == 'test"realm'
    assert result["nonce"] == "123"

    # Single quotes (should be treated as regular chars)
    header = "realm='test', nonce=123"
    result = parse_header_pairs(header)
    assert result["realm"] == "'test'"
    assert result["nonce"] == "123"


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
    auth._challenge = {
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


def test_template_based_header_construction() -> None:
    """Test that the template-based header construction works correctly."""
    auth = DigestAuthMiddleware("testuser", "testpass")
    auth._challenge = {
        "realm": "test-realm",
        "nonce": "test-nonce",
        "qop": "auth",
        "algorithm": "MD5",
        "opaque": "test-opaque",
    }

    # Set last_nonce_bytes to test-nonce to ensure _nonce_count is incremented
    auth._last_nonce_bytes = b"test-nonce"
    auth._nonce_count = 0  # Start with 0, it will be incremented to 1

    # Mock the hash functions to have predictable values
    with mock.patch("hashlib.sha1") as mock_sha1:
        mock_digest = mock.Mock()
        mock_digest.hexdigest.return_value = "deadbeefcafebabe"
        mock_sha1.return_value = mock_digest

        with mock.patch("hashlib.md5") as mock_md5:
            mock_md5_instance = mock.Mock()
            mock_md5_instance.hexdigest.return_value = "abcdef0123456789"
            mock_md5.return_value = mock_md5_instance

            header = auth._encode("GET", URL("http://example.com/test"), "")

    # Split the header into scheme and parameters
    scheme, params_str = header.split(" ", 1)
    assert scheme == "Digest"

    # Parse the parameters into a dictionary
    params = {}
    for param in params_str.split(", "):
        key, value = param.split("=", 1)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]  # Remove quotes
        params[key] = value

    # Check all required fields are present
    assert "username" in params
    assert "realm" in params
    assert "nonce" in params
    assert "uri" in params
    assert "response" in params
    assert "algorithm" in params
    assert "qop" in params
    assert "nc" in params
    assert "cnonce" in params
    assert "opaque" in params

    # Check that fields are quoted correctly
    quoted_fields = [
        "username",
        "realm",
        "nonce",
        "uri",
        "response",
        "opaque",
        "cnonce",
    ]
    unquoted_fields = ["algorithm", "qop", "nc"]

    # Re-check the original header for proper quoting
    for field in quoted_fields:
        assert f'{field}="{params[field]}"' in header

    for field in unquoted_fields:
        assert f"{field}={params[field]}" in header

    # Check specific values
    assert params["username"] == "testuser"
    assert params["realm"] == "test-realm"
    assert params["algorithm"] == "MD5"
    assert params["nc"] == "00000001"  # nonce_count = 1 (incremented from 0)
    assert params["uri"] == "/test"  # path component of URL


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
