"""Test digest authentication middleware for aiohttp client."""

import hashlib
from typing import Optional, Union
from unittest import mock

import pytest
from yarl import URL

from aiohttp import ClientSession, hdrs
from aiohttp.client_exceptions import ClientError
from aiohttp.client_middleware_digest_auth import (
    DigestAuthChallenge,
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


def make_digest_unauthorized_response(
    realm: str = "test-realm",
    nonce: str = "testnonce",
    qop: Optional[str] = None,
    algorithm: str = "MD5",
    opaque: Optional[str] = None,
) -> HTTPUnauthorized:
    """
    Create an HTTPUnauthorized response with a Digest authentication challenge.

    Args:
        realm: The authentication realm
        nonce: The server nonce
        qop: Quality of protection (auth, auth-int, etc.), omitted if None
        algorithm: The hashing algorithm to use
        opaque: The opaque value, omitted if None

    Returns:
        HTTPUnauthorized response with appropriate WWW-Authenticate header

    """
    challenge_parts = [
        f'Digest realm="{realm}"',
        f'nonce="{nonce}"',
    ]

    if qop is not None:
        challenge_parts.append(f'qop="{qop}"')

    if algorithm is not None:
        challenge_parts.append(f"algorithm={algorithm}")

    if opaque is not None:
        challenge_parts.append(f'opaque="{opaque}"')

    return HTTPUnauthorized(
        headers={"WWW-Authenticate": ", ".join(challenge_parts)},
        text="Unauthorized",
    )


# ------------------- DigestAuth Tests -----------------------------------


@pytest.fixture
def digest_auth_mw() -> DigestAuthMiddleware:
    return DigestAuthMiddleware("user", "pass")


@pytest.mark.parametrize(
    ("response_status", "headers", "expected_result", "expected_challenge"),
    [
        # Valid digest with all fields
        (
            401,
            {
                "www-authenticate": 'Digest realm="test", nonce="abc", qop="auth", opaque="xyz", algorithm=MD5'
            },
            True,
            {
                "realm": "test",
                "nonce": "abc",
                "qop": "auth",
                "algorithm": "MD5",
                "opaque": "xyz",
            },
        ),
        # Valid digest without opaque
        (
            401,
            {"www-authenticate": 'Digest realm="test", nonce="abc", qop="auth"'},
            True,
            {"realm": "test", "nonce": "abc", "qop": "auth"},
        ),
        # Non-401 status
        (200, {}, False, {}),  # No challenge should be set
    ],
)
async def test_authenticate_scenarios(
    digest_auth_mw: DigestAuthMiddleware,
    response_status: int,
    headers: dict[str, str],
    expected_result: bool,
    expected_challenge: dict[str, str],
) -> None:
    """Test different authentication scenarios."""
    response = mock.Mock(spec=ClientResponse)
    response.status = response_status
    response.headers = headers

    result = digest_auth_mw._authenticate(response)
    assert result == expected_result

    if expected_result:
        challenge_dict = dict(digest_auth_mw._challenge)
        for key, value in expected_challenge.items():
            assert challenge_dict[key] == value


@pytest.mark.parametrize(
    ("challenge", "expected_error", "description"),
    [
        (
            {},
            "Malformed Digest auth challenge: Missing 'realm' parameter",
            "No challenge set",
        ),
        (
            {"nonce": "abc"},
            "Malformed Digest auth challenge: Missing 'realm' parameter",
            "Missing realm",
        ),
        (
            {"realm": "test"},
            "Malformed Digest auth challenge: Missing 'nonce' parameter",
            "Missing nonce",
        ),
        (
            {"realm": "test", "nonce": ""},
            "Security issue: Digest auth challenge contains empty 'nonce' value",
            "Empty nonce",
        ),
    ],
)
def test_encode_validation_errors(
    digest_auth_mw: DigestAuthMiddleware,
    challenge: dict[str, str],
    expected_error: str,
) -> None:
    """Test validation errors when encoding digest auth headers."""
    digest_auth_mw._challenge = challenge
    with pytest.raises(ClientError, match=expected_error):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_encode_digest_with_md5(digest_auth_mw: DigestAuthMiddleware) -> None:
    digest_auth_mw._challenge = DigestAuthChallenge(
        realm="test", nonce="abc", qop="auth", algorithm="MD5", opaque="xyz"
    )
    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert header.startswith("Digest ")
    assert 'username="user"' in header
    assert "algorithm=MD5" in header


@pytest.mark.parametrize(
    "algorithm", ["MD5-SESS", "SHA-SESS", "SHA-256-SESS", "SHA-512-SESS"]
)
def test_encode_digest_with_sess_algorithms(
    digest_auth_mw: DigestAuthMiddleware, algorithm: str
) -> None:
    """Test that all session-based digest algorithms work correctly."""
    digest_auth_mw._challenge = DigestAuthChallenge(
        realm="test", nonce="abc", qop="auth", algorithm=algorithm
    )
    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert f"algorithm={algorithm}" in header


def test_encode_unsupported_algorithm(digest_auth_mw: DigestAuthMiddleware) -> None:
    """Test that unsupported algorithm raises ClientError."""
    digest_auth_mw._challenge = DigestAuthChallenge(
        realm="test", nonce="abc", algorithm="UNSUPPORTED"
    )
    with pytest.raises(ClientError, match="Unsupported hash algorithm"):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_invalid_qop_rejected() -> None:
    """Test that invalid Quality of Protection values are rejected."""
    auth = DigestAuthMiddleware("u", "p")
    auth._challenge = DigestAuthChallenge(
        realm="r", nonce="n", qop="badvalue", algorithm="MD5"
    )
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

    if algorithm.upper().endswith("-SESS"):
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
@pytest.mark.parametrize("algorithm", sorted(DigestFunctions.keys()))
@pytest.mark.parametrize(
    ("body", "body_str"),
    [
        ("this is a body", "this is a body"),  # String case
        (b"this is a body", "this is a body"),  # Bytes case
    ],
)
def test_digest_response_exact_match(
    qop: str, algorithm: str, body: Union[str, bytes], body_str: str
) -> None:
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
    qop = "auth-int" if "auth-int" in qop else "auth"

    # Create the auth object
    auth = DigestAuthMiddleware(login, password)
    auth._challenge = DigestAuthChallenge(
        realm=realm, nonce=nonce, qop=qop, algorithm=algorithm
    )
    auth._last_nonce_bytes = nonce.encode("utf-8")
    auth._nonce_count = nc

    # Use patch.object to temporarily replace hashlib.sha1 with a mock
    mock_sha1 = mock.Mock()
    mock_sha1.hexdigest.return_value = cnonce

    with mock.patch.object(hashlib, "sha1", return_value=mock_sha1):
        header = auth._encode(method, URL(f"http://host{uri}"), body)

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
        body=body_str,
    )

    # Check that the response digest is exactly correct
    assert f'response="{expected}"' in header


@pytest.mark.parametrize(
    ("header", "expected_result", "description"),
    [
        # Normal quoted values
        (
            'realm="example.com", nonce="12345", qop="auth"',
            {"realm": "example.com", "nonce": "12345", "qop": "auth"},
            "Fully quoted header",
        ),
        # Unquoted values
        (
            "realm=example.com, nonce=12345, qop=auth",
            {"realm": "example.com", "nonce": "12345", "qop": "auth"},
            "Unquoted header",
        ),
        # Mixed quoted/unquoted with commas in quoted values
        (
            'realm="ex,ample", nonce=12345, qop="auth", domain="/test"',
            {"realm": "ex,ample", "nonce": "12345", "qop": "auth", "domain": "/test"},
            "Mixed quoted/unquoted with commas in quoted values",
        ),
        # Header with scheme
        (
            'Digest realm="example.com", nonce="12345", qop="auth"',
            {"realm": "example.com", "nonce": "12345", "qop": "auth"},
            "Header with scheme",
        ),
        # No spaces after commas
        (
            'realm="test",nonce="123",qop="auth"',
            {"realm": "test", "nonce": "123", "qop": "auth"},
            "No spaces after commas",
        ),
        # Extra whitespace
        (
            'realm  =  "test"  ,  nonce  =  "123"',
            {"realm": "test", "nonce": "123"},
            "Extra whitespace",
        ),
        # Escaped quotes
        (
            'realm="test\\"realm", nonce="123"',
            {"realm": 'test"realm', "nonce": "123"},
            "Escaped quotes",
        ),
        # Single quotes (treated as regular chars)
        (
            "realm='test', nonce=123",
            {"realm": "'test'", "nonce": "123"},
            "Single quotes (treated as regular chars)",
        ),
        # Empty header
        ("", {}, "Empty header"),
    ],
)
def test_parse_header_pairs(
    header: str, expected_result: dict[str, str], description: str
) -> None:
    """Test parsing HTTP header pairs with various formats."""
    result = parse_header_pairs(header)
    assert result == expected_result


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
    auth._challenge = DigestAuthChallenge(
        realm='realm"with"quotes',
        nonce='nonce"with"quotes',
        qop="auth",
        algorithm="MD5",
        opaque='opaque"with"quotes',
    )

    header = auth._encode("GET", URL("http://example.com/path"), "")

    # Check that quotes are escaped in the header
    assert 'username="user\\"with\\"quotes"' in header
    assert 'realm="realm\\"with\\"quotes"' in header
    assert 'nonce="nonce\\"with\\"quotes"' in header
    assert 'opaque="opaque\\"with\\"quotes"' in header


def test_template_based_header_construction() -> None:
    """Test that the template-based header construction works correctly."""
    auth = DigestAuthMiddleware("testuser", "testpass")
    auth._challenge = DigestAuthChallenge(
        realm="test-realm",
        nonce="test-nonce",
        qop="auth",
        algorithm="MD5",
        opaque="test-opaque",
    )

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


@pytest.mark.parametrize(
    ("test_string", "expected_escaped", "description"),
    [
        ('value"with"quotes', 'value\\"with\\"quotes', "Basic string with quotes"),
        ("", "", "Empty string"),
        ("no quotes", "no quotes", "String without quotes"),
        ('with"one"quote', 'with\\"one\\"quote', "String with one quoted segment"),
        (
            'many"quotes"in"string',
            'many\\"quotes\\"in\\"string',
            "String with multiple quoted segments",
        ),
        ('""', '\\"\\"', "Just double quotes"),
        ('"', '\\"', "Single double quote"),
        ('already\\"escaped', 'already\\\\"escaped', "Already escaped quotes"),
    ],
)
def test_quote_escaping_functions(
    test_string: str, expected_escaped: str, description: str
) -> None:
    """Test that escape_quotes and unescape_quotes work correctly."""
    # Test escaping
    escaped = escape_quotes(test_string)
    assert escaped == expected_escaped

    # Test unescaping (should return to original)
    unescaped = unescape_quotes(escaped)
    assert unescaped == test_string

    # Test that they're inverse operations
    assert unescape_quotes(escape_quotes(test_string)) == test_string


async def test_middleware_retry_on_401(aiohttp_server: AiohttpServer) -> None:
    """Test that the middleware retries on 401 errors."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge
            raise make_digest_unauthorized_response(
                realm="test", nonce="abc123", qop="auth"
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

    middleware = DigestAuthMiddleware("user", "pass")

    async with ClientSession(middlewares=(middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth


async def test_digest_auth_no_qop(aiohttp_server: AiohttpServer) -> None:
    """Test digest auth with a server that doesn't provide a QoP parameter."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge without qop
            raise make_digest_unauthorized_response(qop=None)

        # Second request should have Authorization header
        auth_header = request.headers.get(hdrs.AUTHORIZATION)
        assert auth_header and auth_header.startswith("Digest ")
        # Successful auth should have no qop param
        assert "qop=" not in auth_header
        assert "nc=" not in auth_header
        assert "cnonce=" not in auth_header

        resp = Response()
        resp.text = "OK"
        return resp

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    middleware = DigestAuthMiddleware("user", "pass")

    async with ClientSession(middlewares=(middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth


async def test_digest_auth_without_opaque(aiohttp_server: AiohttpServer) -> None:
    """Test digest auth with a server that doesn't provide an opaque parameter."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge without opaque
            raise make_digest_unauthorized_response(qop="auth", opaque=None)

        # Second request should have Authorization header
        auth_header = request.headers.get(hdrs.AUTHORIZATION)
        assert auth_header and auth_header.startswith("Digest ")
        # Successful auth should have no opaque param
        assert "opaque=" not in auth_header

        resp = Response()
        resp.text = "OK"
        return resp

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    middleware = DigestAuthMiddleware("user", "pass")

    async with ClientSession(middlewares=(middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth


@pytest.mark.parametrize(
    ("www_authenticate", "description"),
    [
        (None, "No WWW-Authenticate header"),
        ("DigestWithoutSpace", "No space after scheme"),
        ('Basic realm="test"', "Not a Digest scheme"),
        ("Digest ", "Empty parameters"),
        ("Digest =invalid, format", "Invalid parameter format"),
    ],
)
async def test_auth_header_no_retry(
    aiohttp_server: AiohttpServer, www_authenticate: str, description: str
) -> None:
    """Test that middleware doesn't retry with invalid WWW-Authenticate headers."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        # First (and only) request returns 401
        headers = {}
        if www_authenticate is not None:
            headers["WWW-Authenticate"] = www_authenticate

        # Use a custom HTTPUnauthorized instead of the helper since
        # we're specifically testing malformed headers
        raise HTTPUnauthorized(
            headers=headers,
            text="Unauthorized",
        )

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    middleware = DigestAuthMiddleware("user", "pass")

    async with ClientSession(middlewares=(middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 401

    # No retry should happen
    assert request_count == 1
