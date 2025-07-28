"""Test digest authentication middleware for aiohttp client."""

import io
import re
from hashlib import md5, sha1
from typing import Generator, Literal, Union
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
from aiohttp.payload import BytesIOPayload
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
async def test_encode_validation_errors(
    digest_auth_mw: DigestAuthMiddleware,
    challenge: DigestAuthChallenge,
    expected_error: str,
) -> None:
    """Test validation errors when encoding digest auth headers."""
    digest_auth_mw._challenge = challenge
    with pytest.raises(ClientError, match=expected_error):
        await digest_auth_mw._encode("GET", URL("http://example.com/resource"), b"")


async def test_encode_digest_with_md5(
    auth_mw_with_challenge: DigestAuthMiddleware,
) -> None:
    header = await auth_mw_with_challenge._encode(
        "GET", URL("http://example.com/resource"), b""
    )
    assert header.startswith("Digest ")
    assert 'username="user"' in header
    assert "algorithm=MD5" in header


@pytest.mark.parametrize(
    "algorithm", ["MD5-SESS", "SHA-SESS", "SHA-256-SESS", "SHA-512-SESS"]
)
async def test_encode_digest_with_sess_algorithms(
    digest_auth_mw: DigestAuthMiddleware,
    qop_challenge: DigestAuthChallenge,
    algorithm: str,
) -> None:
    """Test that all session-based digest algorithms work correctly."""
    # Create a modified challenge with the test algorithm
    challenge = qop_challenge.copy()
    challenge["algorithm"] = algorithm
    digest_auth_mw._challenge = challenge

    header = await digest_auth_mw._encode(
        "GET", URL("http://example.com/resource"), b""
    )
    assert f"algorithm={algorithm}" in header


async def test_encode_unsupported_algorithm(
    digest_auth_mw: DigestAuthMiddleware, basic_challenge: DigestAuthChallenge
) -> None:
    """Test that unsupported algorithm raises ClientError."""
    # Create a modified challenge with an unsupported algorithm
    challenge = basic_challenge.copy()
    challenge["algorithm"] = "UNSUPPORTED"
    digest_auth_mw._challenge = challenge

    with pytest.raises(ClientError, match="Unsupported hash algorithm"):
        await digest_auth_mw._encode("GET", URL("http://example.com/resource"), b"")


@pytest.mark.parametrize("algorithm", ["MD5", "MD5-SESS", "SHA-256"])
async def test_encode_algorithm_case_preservation_uppercase(
    digest_auth_mw: DigestAuthMiddleware,
    qop_challenge: DigestAuthChallenge,
    algorithm: str,
) -> None:
    """Test that uppercase algorithm case is preserved in the response header."""
    # Create a challenge with the specific algorithm case
    challenge = qop_challenge.copy()
    challenge["algorithm"] = algorithm
    digest_auth_mw._challenge = challenge

    header = await digest_auth_mw._encode(
        "GET", URL("http://example.com/resource"), b""
    )

    # The algorithm in the response should match the exact case from the challenge
    assert f"algorithm={algorithm}" in header


@pytest.mark.parametrize("algorithm", ["md5", "MD5-sess", "sha-256"])
async def test_encode_algorithm_case_preservation_lowercase(
    digest_auth_mw: DigestAuthMiddleware,
    qop_challenge: DigestAuthChallenge,
    algorithm: str,
) -> None:
    """Test that lowercase/mixed-case algorithm is preserved in the response header."""
    # Create a challenge with the specific algorithm case
    challenge = qop_challenge.copy()
    challenge["algorithm"] = algorithm
    digest_auth_mw._challenge = challenge

    header = await digest_auth_mw._encode(
        "GET", URL("http://example.com/resource"), b""
    )

    # The algorithm in the response should match the exact case from the challenge
    assert f"algorithm={algorithm}" in header
    # Also verify it's not the uppercase version
    assert f"algorithm={algorithm.upper()}" not in header


async def test_invalid_qop_rejected(
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
        await digest_auth_mw._encode("GET", URL("http://example.com"), b"")


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
        (b"", ""),  # Bytes case
        (
            BytesIOPayload(io.BytesIO(b"this is a body")),
            "this is a body",
        ),  # BytesIOPayload case
    ],
)
async def test_digest_response_exact_match(
    qop: str,
    algorithm: str,
    body: Union[Literal[b""], BytesIOPayload],
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

    header = await auth._encode(method, URL(f"http://host{uri}"), body)

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


async def test_escaping_quotes_in_auth_header() -> None:
    """Test that double quotes are properly escaped in auth header."""
    auth = DigestAuthMiddleware('user"with"quotes', "pass")
    auth._challenge = DigestAuthChallenge(
        realm='realm"with"quotes',
        nonce='nonce"with"quotes',
        qop="auth",
        algorithm="MD5",
        opaque='opaque"with"quotes',
    )

    header = await auth._encode("GET", URL("http://example.com/path"), b"")

    # Check that quotes are escaped in the header
    assert 'username="user\\"with\\"quotes"' in header
    assert 'realm="realm\\"with\\"quotes"' in header
    assert 'nonce="nonce\\"with\\"quotes"' in header
    assert 'opaque="opaque\\"with\\"quotes"' in header


async def test_template_based_header_construction(
    auth_mw_with_challenge: DigestAuthMiddleware,
    mock_sha1_digest: mock.MagicMock,
    mock_md5_digest: mock.MagicMock,
) -> None:
    """Test that the template-based header construction works correctly."""
    header = await auth_mw_with_challenge._encode(
        "GET", URL("http://example.com/test"), b""
    )

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


async def test_preemptive_auth_disabled(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that preemptive authentication can be disabled."""
    digest_auth_mw = DigestAuthMiddleware("user", "pass", preemptive=False)
    request_count = 0
    auth_headers = []

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1
        auth_headers.append(request.headers.get(hdrs.AUTHORIZATION))

        if not request.headers.get(hdrs.AUTHORIZATION):
            # Return 401 with digest challenge
            challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        return Response(text="OK")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        # First request will get 401 and store challenge
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"

        # Second request should NOT send auth preemptively (preemptive=False)
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"

    # With preemptive disabled, each request needs 401 challenge first
    assert request_count == 4  # 2 requests * 2 (401 + retry)
    assert auth_headers[0] is None  # First request has no auth
    assert auth_headers[1] is not None  # Second request has auth after 401
    assert auth_headers[2] is None  # Third request has no auth (preemptive disabled)
    assert auth_headers[3] is not None  # Fourth request has auth after 401


async def test_preemptive_auth_with_stale_nonce(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test preemptive auth handles stale nonce responses correctly."""
    digest_auth_mw = DigestAuthMiddleware("user", "pass", preemptive=True)
    request_count = 0
    current_nonce = 0

    async def handler(request: Request) -> Response:
        nonlocal request_count, current_nonce
        request_count += 1

        auth_header = request.headers.get(hdrs.AUTHORIZATION)

        if not auth_header:
            # First request without auth
            current_nonce = 1
            challenge = f'Digest realm="test", nonce="nonce{current_nonce}", qop="auth", algorithm=MD5'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        # For the second set of requests, always consider the first nonce stale
        if request_count == 3 and current_nonce == 1:
            # Stale nonce - request new auth with stale=true
            current_nonce = 2
            challenge = f'Digest realm="test", nonce="nonce{current_nonce}", qop="auth", algorithm=MD5, stale=true'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized - Stale nonce",
            )

        return Response(text="OK")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        # First request - will get 401, then retry with auth
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"

        # Second request - will use preemptive auth with nonce1, get 401 stale, retry with nonce2
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"

    # Verify the expected flow:
    # Request 1: no auth -> 401
    # Request 2: retry with auth -> 200
    # Request 3: preemptive auth with old nonce -> 401 stale
    # Request 4: retry with new nonce -> 200
    assert request_count == 4


async def test_preemptive_auth_updates_nonce_count(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that preemptive auth properly increments nonce count."""
    digest_auth_mw = DigestAuthMiddleware("user", "pass", preemptive=True)
    request_count = 0
    nonce_counts = []

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        auth_header = request.headers.get(hdrs.AUTHORIZATION)

        if not auth_header:
            # First request without auth
            challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        # Extract nc (nonce count) from auth header
        nc_match = auth_header.split("nc=")[1].split(",")[0].strip()
        nonce_counts.append(nc_match)

        return Response(text="OK")

    app = Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        # Make multiple requests to see nonce count increment
        for _ in range(3):
            async with session.get(server.make_url("/")) as resp:
                assert resp.status == 200
                await resp.text()

    # First request has no auth, then gets 401 and retries with nc=00000001
    # Second and third requests use preemptive auth with nc=00000002 and nc=00000003
    assert len(nonce_counts) == 3
    assert nonce_counts[0] == "00000001"
    assert nonce_counts[1] == "00000002"
    assert nonce_counts[2] == "00000003"


async def test_preemptive_auth_respects_protection_space(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that preemptive auth only applies to URLs within the protection space."""
    digest_auth_mw = DigestAuthMiddleware("user", "pass", preemptive=True)
    request_count = 0
    auth_headers = []
    requested_paths = []

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1
        auth_headers.append(request.headers.get(hdrs.AUTHORIZATION))
        requested_paths.append(request.path)

        if not request.headers.get(hdrs.AUTHORIZATION):
            # Return 401 with digest challenge including domain parameter
            challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5, domain="/api /admin"'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        return Response(text="OK")

    app = Application()
    app.router.add_get("/api/endpoint", handler)
    app.router.add_get("/admin/panel", handler)
    app.router.add_get("/public/page", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        # First request to /api/endpoint - should get 401 and retry with auth
        async with session.get(server.make_url("/api/endpoint")) as resp:
            assert resp.status == 200

        # Second request to /api/endpoint - should use preemptive auth (in protection space)
        async with session.get(server.make_url("/api/endpoint")) as resp:
            assert resp.status == 200

        # Third request to /admin/panel - should use preemptive auth (in protection space)
        async with session.get(server.make_url("/admin/panel")) as resp:
            assert resp.status == 200

        # Fourth request to /public/page - should NOT use preemptive auth (outside protection space)
        async with session.get(server.make_url("/public/page")) as resp:
            assert resp.status == 200

    # Verify auth headers
    assert auth_headers[0] is None  # First request to /api/endpoint - no auth
    assert auth_headers[1] is not None  # Retry with auth
    assert (
        auth_headers[2] is not None
    )  # Second request to /api/endpoint - preemptive auth
    assert auth_headers[3] is not None  # Request to /admin/panel - preemptive auth
    assert auth_headers[4] is None  # First request to /public/page - no preemptive auth
    assert auth_headers[5] is not None  # Retry with auth

    # Verify paths
    assert requested_paths == [
        "/api/endpoint",  # Initial request
        "/api/endpoint",  # Retry with auth
        "/api/endpoint",  # Second request with preemptive auth
        "/admin/panel",  # Request with preemptive auth
        "/public/page",  # Initial request (no preemptive auth)
        "/public/page",  # Retry with auth
    ]


async def test_preemptive_auth_with_absolute_domain_uris(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test preemptive auth with absolute URIs in domain parameter."""
    digest_auth_mw = DigestAuthMiddleware("user", "pass", preemptive=True)
    request_count = 0
    auth_headers = []

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1
        auth_headers.append(request.headers.get(hdrs.AUTHORIZATION))

        if not request.headers.get(hdrs.AUTHORIZATION):
            # Return 401 with digest challenge including absolute URI in domain
            server_url = str(request.url.with_path("/protected"))
            challenge = f'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5, domain="{server_url}"'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        return Response(text="OK")

    app = Application()
    app.router.add_get("/protected/resource", handler)
    app.router.add_get("/unprotected/resource", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        # First request to protected resource
        async with session.get(server.make_url("/protected/resource")) as resp:
            assert resp.status == 200

        # Second request to protected resource - should use preemptive auth
        async with session.get(server.make_url("/protected/resource")) as resp:
            assert resp.status == 200

        # Request to unprotected resource - should NOT use preemptive auth
        async with session.get(server.make_url("/unprotected/resource")) as resp:
            assert resp.status == 200

    # Verify auth pattern
    assert auth_headers[0] is None  # First request - no auth
    assert auth_headers[1] is not None  # Retry with auth
    assert auth_headers[2] is not None  # Second request - preemptive auth
    assert auth_headers[3] is None  # Unprotected resource - no preemptive auth
    assert auth_headers[4] is not None  # Retry with auth


async def test_preemptive_auth_without_domain_uses_origin(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that preemptive auth without domain parameter applies to entire origin."""
    digest_auth_mw = DigestAuthMiddleware("user", "pass", preemptive=True)
    request_count = 0
    auth_headers = []

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1
        auth_headers.append(request.headers.get(hdrs.AUTHORIZATION))

        if not request.headers.get(hdrs.AUTHORIZATION):
            # Return 401 with digest challenge without domain parameter
            challenge = 'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        return Response(text="OK")

    app = Application()
    app.router.add_get("/path1", handler)
    app.router.add_get("/path2", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(digest_auth_mw,)) as session:
        # First request
        async with session.get(server.make_url("/path1")) as resp:
            assert resp.status == 200

        # Second request to different path - should still use preemptive auth
        async with session.get(server.make_url("/path2")) as resp:
            assert resp.status == 200

    # Verify auth pattern
    assert auth_headers[0] is None  # First request - no auth
    assert auth_headers[1] is not None  # Retry with auth
    assert (
        auth_headers[2] is not None
    )  # Second request - preemptive auth (entire origin)


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


@pytest.mark.parametrize(
    ("protection_space_url", "request_url", "expected"),
    [
        # Exact match
        ("http://example.com/app1", "http://example.com/app1", True),
        # Path with trailing slash should match
        ("http://example.com/app1", "http://example.com/app1/", True),
        # Subpaths should match
        ("http://example.com/app1", "http://example.com/app1/resource", True),
        ("http://example.com/app1", "http://example.com/app1/sub/path", True),
        # Should NOT match different paths that start with same prefix
        ("http://example.com/app1", "http://example.com/app1xx", False),
        ("http://example.com/app1", "http://example.com/app123", False),
        # Protection space with trailing slash
        ("http://example.com/app1/", "http://example.com/app1/", True),
        ("http://example.com/app1/", "http://example.com/app1/resource", True),
        (
            "http://example.com/app1/",
            "http://example.com/app1",
            False,
        ),  # No trailing slash
        # Root protection space
        ("http://example.com/", "http://example.com/", True),
        ("http://example.com/", "http://example.com/anything", True),
        ("http://example.com/", "http://example.com", False),  # No trailing slash
        # Different origins should not match
        ("http://example.com/app1", "https://example.com/app1", False),
        ("http://example.com/app1", "http://other.com/app1", False),
        ("http://example.com:8080/app1", "http://example.com/app1", False),
    ],
    ids=[
        "exact_match",
        "path_with_trailing_slash",
        "subpath_match",
        "deep_subpath_match",
        "no_match_app1xx",
        "no_match_app123",
        "protection_with_slash_exact",
        "protection_with_slash_subpath",
        "protection_with_slash_no_match_without",
        "root_protection_exact",
        "root_protection_subpath",
        "root_protection_no_match_without_slash",
        "different_scheme",
        "different_host",
        "different_port",
    ],
)
def test_in_protection_space(
    digest_auth_mw: DigestAuthMiddleware,
    protection_space_url: str,
    request_url: str,
    expected: bool,
) -> None:
    """Test _in_protection_space method with various URL patterns."""
    digest_auth_mw._protection_space = [protection_space_url]
    result = digest_auth_mw._in_protection_space(URL(request_url))
    assert result == expected


def test_in_protection_space_multiple_spaces(
    digest_auth_mw: DigestAuthMiddleware,
) -> None:
    """Test _in_protection_space with multiple protection spaces."""
    digest_auth_mw._protection_space = [
        "http://example.com/api",
        "http://example.com/admin/",
        "http://example.com/secure/area",
    ]

    # Test various URLs
    assert digest_auth_mw._in_protection_space(URL("http://example.com/api")) is True
    assert digest_auth_mw._in_protection_space(URL("http://example.com/api/v1")) is True
    assert (
        digest_auth_mw._in_protection_space(URL("http://example.com/admin/panel"))
        is True
    )
    assert (
        digest_auth_mw._in_protection_space(
            URL("http://example.com/secure/area/resource")
        )
        is True
    )

    # These should not match
    assert digest_auth_mw._in_protection_space(URL("http://example.com/apiv2")) is False
    assert (
        digest_auth_mw._in_protection_space(URL("http://example.com/admin")) is False
    )  # No trailing slash
    assert (
        digest_auth_mw._in_protection_space(URL("http://example.com/secure")) is False
    )
    assert digest_auth_mw._in_protection_space(URL("http://example.com/other")) is False


async def test_case_sensitive_algorithm_server(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test authentication with a server that requires exact algorithm case matching.

    This simulates servers like Prusa printers that expect the algorithm
    to be returned with the exact same case as sent in the challenge.
    """
    digest_auth_mw = DigestAuthMiddleware("testuser", "testpass")
    request_count = 0
    auth_algorithms: list[str] = []

    async def handler(request: Request) -> Response:
        nonlocal request_count
        request_count += 1

        if not (auth_header := request.headers.get(hdrs.AUTHORIZATION)):
            # Send challenge with lowercase-sess algorithm (like Prusa)
            challenge = 'Digest realm="Administrator", nonce="test123", qop="auth", algorithm="MD5-sess", opaque="xyz123"'
            return Response(
                status=401,
                headers={"WWW-Authenticate": challenge},
                text="Unauthorized",
            )

        # Extract algorithm from auth response
        algo_match = re.search(r"algorithm=([^,\s]+)", auth_header)
        assert algo_match is not None
        auth_algorithms.append(algo_match.group(1))

        # Case-sensitive server: only accept exact case match
        assert "algorithm=MD5-sess" in auth_header
        return Response(text="Success")

    app = Application()
    app.router.add_get("/api/test", handler)
    server = await aiohttp_server(app)

    async with (
        ClientSession(middlewares=(digest_auth_mw,)) as session,
        session.get(server.make_url("/api/test")) as resp,
    ):
        assert resp.status == 200
        text = await resp.text()
        assert text == "Success"

    # Verify the middleware preserved the exact algorithm case
    assert request_count == 2  # Initial 401 + successful retry
    assert len(auth_algorithms) == 1
    assert auth_algorithms[0] == "MD5-sess"  # Not "MD5-SESS"
