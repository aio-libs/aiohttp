"""Test digest authentication middleware for aiohttp client."""

from hashlib import md5, sha1
from typing import Generator, Union
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


@pytest.fixture
def digest_auth_mw() -> DigestAuthMiddleware:
    return DigestAuthMiddleware("user", "pass")


@pytest.fixture
def basic_challenge() -> DigestAuthChallenge:
    """Return a basic digest auth challenge with required fields only."""
    return DigestAuthChallenge(realm="test", nonce="abc")


@pytest.fixture
def complete_challenge() -> DigestAuthChallenge:
    """Return a complete digest auth challenge with all fields."""
    return DigestAuthChallenge(
        realm="test", nonce="abc", qop="auth", algorithm="MD5", opaque="xyz"
    )


@pytest.fixture
def qop_challenge() -> DigestAuthChallenge:
    """Return a digest auth challenge with qop field."""
    return DigestAuthChallenge(realm="test", nonce="abc", qop="auth")


@pytest.fixture
def no_qop_challenge() -> DigestAuthChallenge:
    """Return a digest auth challenge without qop."""
    return DigestAuthChallenge(realm="test-realm", nonce="testnonce", algorithm="MD5")


@pytest.fixture
def auth_mw_with_challenge(
    digest_auth_mw: DigestAuthMiddleware, complete_challenge: DigestAuthChallenge
) -> DigestAuthMiddleware:
    """Return a digest auth middleware with pre-set challenge."""
    digest_auth_mw._challenge = complete_challenge
    digest_auth_mw._last_nonce_bytes = complete_challenge["nonce"].encode("utf-8")
    digest_auth_mw._nonce_count = 0
    return digest_auth_mw


@pytest.fixture
def mock_sha1_digest() -> Generator[mock.MagicMock, None, None]:
    """Mock SHA1 to return a predictable value for testing."""
    mock_digest = mock.MagicMock(spec=sha1())
    mock_digest.hexdigest.return_value = "deadbeefcafebabe"
    with mock.patch("hashlib.sha1", return_value=mock_digest) as patched:
        yield patched


@pytest.fixture
def mock_md5_digest() -> Generator[mock.MagicMock, None, None]:
    """Mock MD5 to return a predictable value for testing."""
    mock_digest = mock.MagicMock(spec=md5())
    mock_digest.hexdigest.return_value = "abcdef0123456789"
    with mock.patch("hashlib.md5", return_value=mock_digest) as patched:
        yield patched


@pytest.mark.parametrize(
    ("response_status", "headers", "expected_result", "expected_challenge"),
    [
        # Valid digest with all fields
        (
            401,
            {
                "www-authenticate": 'Digest realm="test", nonce="abc", '
                'qop="auth", opaque="xyz", algorithm=MD5'
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
    response = mock.MagicMock(spec=ClientResponse)
    response.status = response_status
    response.headers = headers

    result = digest_auth_mw._authenticate(response)
    assert result == expected_result

    if expected_result:
        challenge_dict = dict(digest_auth_mw._challenge)
        for key, value in expected_challenge.items():
            assert challenge_dict[key] == value


@pytest.mark.parametrize(
    ("challenge", "expected_error"),
    [
        (
            DigestAuthChallenge(),
            "Malformed Digest auth challenge: Missing 'realm' parameter",
        ),
        (
            DigestAuthChallenge(nonce="abc"),
            "Malformed Digest auth challenge: Missing 'realm' parameter",
        ),
        (
            DigestAuthChallenge(realm="test"),
            "Malformed Digest auth challenge: Missing 'nonce' parameter",
        ),
        (
            DigestAuthChallenge(realm="test", nonce=""),
            "Security issue: Digest auth challenge contains empty 'nonce' value",
        ),
    ],
)
def test_encode_validation_errors(
    digest_auth_mw: DigestAuthMiddleware,
    challenge: DigestAuthChallenge,
    expected_error: str,
) -> None:
    """Test validation errors when encoding digest auth headers."""
    digest_auth_mw._challenge = challenge
    with pytest.raises(ClientError, match=expected_error):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_encode_digest_with_md5(auth_mw_with_challenge: DigestAuthMiddleware) -> None:
    header = auth_mw_with_challenge._encode(
        "GET", URL("http://example.com/resource"), ""
    )
    assert header.startswith("Digest ")
    assert 'username="user"' in header
    assert "algorithm=MD5" in header


@pytest.mark.parametrize(
    "algorithm", ["MD5-SESS", "SHA-SESS", "SHA-256-SESS", "SHA-512-SESS"]
)
def test_encode_digest_with_sess_algorithms(
    digest_auth_mw: DigestAuthMiddleware,
    qop_challenge: DigestAuthChallenge,
    algorithm: str,
) -> None:
    """Test that all session-based digest algorithms work correctly."""
    # Create a modified challenge with the test algorithm
    challenge = qop_challenge.copy()
    challenge["algorithm"] = algorithm
    digest_auth_mw._challenge = challenge

    header = digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")
    assert f"algorithm={algorithm}" in header


def test_encode_unsupported_algorithm(
    digest_auth_mw: DigestAuthMiddleware, basic_challenge: DigestAuthChallenge
) -> None:
    """Test that unsupported algorithm raises ClientError."""
    # Create a modified challenge with an unsupported algorithm
    challenge = basic_challenge.copy()
    challenge["algorithm"] = "UNSUPPORTED"
    digest_auth_mw._challenge = challenge

    with pytest.raises(ClientError, match="Unsupported hash algorithm"):
        digest_auth_mw._encode("GET", URL("http://example.com/resource"), "")


def test_invalid_qop_rejected(
    digest_auth_mw: DigestAuthMiddleware, basic_challenge: DigestAuthChallenge
) -> None:
    """Test that invalid Quality of Protection values are rejected."""
    # Use bad QoP value to trigger error
    challenge = basic_challenge.copy()
    challenge["qop"] = "badvalue"
    challenge["algorithm"] = "MD5"
    digest_auth_mw._challenge = challenge

    # This should raise an error about unsupported QoP
    with pytest.raises(ClientError, match="Unsupported Quality of Protection"):
        digest_auth_mw._encode("GET", URL("http://example.com"), "")


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
        return KD(HA1, f"{nonce}:{nc}:{cnonce}:{qop}:{HA2}")
    else:
        return KD(HA1, f"{nonce}:{HA2}")


@pytest.mark.parametrize("qop", ["auth", "auth-int", "auth,auth-int", ""])
@pytest.mark.parametrize("algorithm", sorted(DigestFunctions.keys()))
@pytest.mark.parametrize(
    ("body", "body_str"),
    [
        ("this is a body", "this is a body"),  # String case
        (b"this is a body", "this is a body"),  # Bytes case
    ],
)
def test_digest_response_exact_match(
    qop: str,
    algorithm: str,
    body: Union[str, bytes],
    body_str: str,
    mock_sha1_digest: mock.MagicMock,
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
    ("header", "expected_result"),
    [
        # Normal quoted values
        (
            'realm="example.com", nonce="12345", qop="auth"',
            {"realm": "example.com", "nonce": "12345", "qop": "auth"},
        ),
        # Unquoted values
        (
            "realm=example.com, nonce=12345, qop=auth",
            {"realm": "example.com", "nonce": "12345", "qop": "auth"},
        ),
        # Mixed quoted/unquoted with commas in quoted values
        (
            'realm="ex,ample", nonce=12345, qop="auth", domain="/test"',
            {
                "realm": "ex,ample",
                "nonce": "12345",
                "qop": "auth",
                "domain": "/test",
            },
        ),
        # Header with scheme
        (
            'Digest realm="example.com", nonce="12345", qop="auth"',
            {"realm": "example.com", "nonce": "12345", "qop": "auth"},
        ),
        # No spaces after commas
        (
            'realm="test",nonce="123",qop="auth"',
            {"realm": "test", "nonce": "123", "qop": "auth"},
        ),
        # Extra whitespace
        (
            'realm  =  "test"  ,  nonce  =  "123"',
            {"realm": "test", "nonce": "123"},
        ),
        # Escaped quotes
        (
            'realm="test\\"realm", nonce="123"',
            {"realm": 'test"realm', "nonce": "123"},
        ),
        # Single quotes (treated as regular chars)
        (
            "realm='test', nonce=123",
            {"realm": "'test'", "nonce": "123"},
        ),
        # Empty header
        ("", {}),
    ],
    ids=[
        "fully_quoted_header",
        "unquoted_header",
        "mixed_quoted_unquoted_with_commas",
        "header_with_scheme",
        "no_spaces_after_commas",
        "extra_whitespace",
        "escaped_quotes",
        "single_quotes_as_regular_chars",
        "empty_header",
    ],
)
def test_parse_header_pairs(header: str, expected_result: dict[str, str]) -> None:
    """Test parsing HTTP header pairs with various formats."""
    result = parse_header_pairs(header)
    assert result == expected_result


def test_digest_auth_middleware_callable(digest_auth_mw: DigestAuthMiddleware) -> None:
    """Test that DigestAuthMiddleware is callable."""
    assert callable(digest_auth_mw)


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


def test_template_based_header_construction(
    auth_mw_with_challenge: DigestAuthMiddleware,
    mock_sha1_digest: mock.MagicMock,
    mock_md5_digest: mock.MagicMock,
) -> None:
    """Test that the template-based header construction works correctly."""
    header = auth_mw_with_challenge._encode("GET", URL("http://example.com/test"), "")

    # Split the header into scheme and parameters
    scheme, params_str = header.split(" ", 1)
    assert scheme == "Digest"

    # Parse the parameters into a dictionary
    params = {
        key: value[1:-1] if value.startswith('"') and value.endswith('"') else value
        for key, value in (param.split("=", 1) for param in params_str.split(", "))
    }

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
    assert params["username"] == "user"
    assert params["realm"] == "test"
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


async def test_middleware_retry_on_401(
    aiohttp_server: AiohttpServer, digest_auth_mw: DigestAuthMiddleware
) -> None:
    """Test that the middleware retries on 401 errors."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge
            challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        # Second request should have Authorization header
        auth_header = request.headers.get(hdrs.AUTHORIZATION)
        if auth_header and auth_header.startswith("Digest "):
            # Return success response
            return Response(text="OK")

        # This branch should not be reached in the tests
        assert False, "This branch should not be reached"

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth


async def test_digest_auth_no_qop(
    aiohttp_server: AiohttpServer,
    digest_auth_mw: DigestAuthMiddleware,
    no_qop_challenge: DigestAuthChallenge,
    mock_sha1_digest: mock.MagicMock,
) -> None:
    """Test digest auth with a server that doesn't provide a QoP parameter."""
    request_count = 0
    realm = no_qop_challenge["realm"]
    nonce = no_qop_challenge["nonce"]
    algorithm = no_qop_challenge["algorithm"]
    username = "user"
    password = "pass"
    uri = "/"

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge without qop
            challenge = (
                f'Digest realm="{realm}", nonce="{nonce}", algorithm={algorithm}'
            )
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        # Second request should have Authorization header
        auth_header = request.headers.get(hdrs.AUTHORIZATION)
        assert auth_header and auth_header.startswith("Digest ")

        # Successful auth should have no qop param
        assert "qop=" not in auth_header
        assert "nc=" not in auth_header
        assert "cnonce=" not in auth_header

        expected_digest = compute_expected_digest(
            algorithm=algorithm,
            username=username,
            password=password,
            realm=realm,
            nonce=nonce,
            uri=uri,
            method="GET",
            qop="",  # This is the key part - explicitly setting qop=""
            nc="",  # Not needed for non-qop digest
            cnonce="",  # Not needed for non-qop digest
        )
        # We mock the cnonce, so we can check the expected digest
        assert expected_digest in auth_header

        return Response(text="OK")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth


async def test_digest_auth_without_opaque(
    aiohttp_server: AiohttpServer, digest_auth_mw: DigestAuthMiddleware
) -> None:
    """Test digest auth with a server that doesn't provide an opaque parameter."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            # First request returns 401 with digest challenge without opaque
            challenge = (
                'Digest realm="test-realm", nonce="testnonce", '
                'qop="auth", algorithm=MD5'
            )
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        # Second request should have Authorization header
        auth_header = request.headers.get(hdrs.AUTHORIZATION)
        assert auth_header and auth_header.startswith("Digest ")
        # Successful auth should have no opaque param
        assert "opaque=" not in auth_header

        return Response(text="OK")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text_content = await resp.text()
            assert text_content == "OK"

    assert request_count == 2  # Initial request + retry with auth


@pytest.mark.parametrize(
    "www_authenticate",
    [
        None,
        "DigestWithoutSpace",
        'Basic realm="test"',
        "Digest ",
        "Digest =invalid, format",
    ],
)
async def test_auth_header_no_retry(
    aiohttp_server: AiohttpServer,
    www_authenticate: str,
    digest_auth_mw: DigestAuthMiddleware,
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
        return Response(status=401, headers=headers, text="Unauthorized")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 401

    # No retry should happen
    assert request_count == 1


async def test_direct_success_no_auth_needed(
    aiohttp_server: AiohttpServer, digest_auth_mw: DigestAuthMiddleware
) -> None:
    """Test middleware with a direct 200 response with no auth challenge."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        # Return success without auth challenge
        return Response(text="OK")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        async with session.get(server.make_url("/")) as resp:
            text = await resp.text()
            assert resp.status == 200
            assert text == "OK"

    # Verify only one request was made
    assert request_count == 1


async def test_no_retry_on_second_401(
    aiohttp_server: AiohttpServer, digest_auth_mw: DigestAuthMiddleware
) -> None:
    """Test digest auth does not retry on second 401."""
    request_count = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        # Always return 401 challenge
        challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5'
        return Response(
            status=401,
            headers={"WWW-Authenticate": challenge},
            text="Unauthorized",
        )

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create a session that uses the digest auth middleware
    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        async with session.get(server.make_url("/")) as resp:
            await resp.text()
            assert resp.status == 401

    # Verify we made exactly 2 requests (initial + 1 retry)
    assert request_count == 2


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (200, {}, False),
        (401, {"www-authenticate": ""}, False),
        (401, {"www-authenticate": "DigestWithoutSpace"}, False),
        (401, {"www-authenticate": "Basic realm=test"}, False),
        (401, {"www-authenticate": "Digest "}, False),
        (401, {"www-authenticate": "Digest =invalid, format"}, False),
    ],
    ids=[
        "different_status_code",
        "empty_www_authenticate_header",
        "no_space_after_scheme",
        "different_scheme",
        "empty_parameters",
        "malformed_parameters",
    ],
)
def test_authenticate_with_malformed_headers(
    digest_auth_mw: DigestAuthMiddleware,
    status: int,
    headers: dict[str, str],
    expected: bool,
) -> None:
    """Test _authenticate method with various edge cases."""
    response = mock.MagicMock(spec=ClientResponse)
    response.status = status
    response.headers = headers

    result = digest_auth_mw._authenticate(response)
    assert result == expected
