"""Tests for client middleware."""

import json
import socket
from typing import Dict, List, NoReturn, Optional, Union

import pytest

from aiohttp import (
    ClientError,
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    TCPConnector,
    web,
)
from aiohttp.abc import ResolveResult
from aiohttp.client_middlewares import build_client_middlewares
from aiohttp.client_proto import ResponseHandler
from aiohttp.pytest_plugin import AiohttpServer
from aiohttp.resolver import ThreadedResolver
from aiohttp.tracing import Trace


class BlockedByMiddleware(ClientError):
    """Custom exception for when middleware blocks a request."""


async def test_client_middleware_called(aiohttp_server: AiohttpServer) -> None:
    """Test that client middleware is called."""
    middleware_called = False
    request_count = 0

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1
        return web.Response(text=f"OK {request_count}")

    async def test_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal middleware_called
        middleware_called = True
        response = await handler(request)
        return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(test_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK 1"

    assert middleware_called is True
    assert request_count == 1


async def test_client_middleware_retry(aiohttp_server: AiohttpServer) -> None:
    """Test that middleware can trigger retries."""
    request_count = 0

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return web.Response(status=503)
        return web.Response(text=f"OK {request_count}")

    async def retry_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        response = None
        for _ in range(2):  # pragma: no branch
            response = await handler(request)
            if response.ok:
                return response
        assert False, "not reachable in test"

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(retry_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK 2"

    assert request_count == 2


async def test_client_middleware_per_request(aiohttp_server: AiohttpServer) -> None:
    """Test that middleware can be specified per request."""
    session_middleware_called = False
    request_middleware_called = False

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK")

    async def session_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal session_middleware_called
        session_middleware_called = True
        response = await handler(request)
        return response

    async def request_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal request_middleware_called
        request_middleware_called = True
        response = await handler(request)
        return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Request with session middleware
    async with ClientSession(middlewares=(session_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200

    assert session_middleware_called is True
    assert request_middleware_called is False

    # Reset flags
    session_middleware_called = False

    # Request with override middleware
    async with ClientSession(middlewares=(session_middleware,)) as session:
        async with session.get(
            server.make_url("/"), middlewares=(request_middleware,)
        ) as resp:
            assert resp.status == 200

    assert session_middleware_called is False
    assert request_middleware_called is True


async def test_multiple_client_middlewares(aiohttp_server: AiohttpServer) -> None:
    """Test that multiple middlewares are executed in order."""
    calls: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK")

    async def middleware1(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        calls.append("before1")
        response = await handler(request)
        calls.append("after1")
        return response

    async def middleware2(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        calls.append("before2")
        response = await handler(request)
        calls.append("after2")
        return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(middleware1, middleware2)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200

    # Middlewares are applied in reverse order (like server middlewares)
    # So middleware1 wraps middleware2
    assert calls == ["before1", "before2", "after2", "after1"]


async def test_client_middleware_auth_example(aiohttp_server: AiohttpServer) -> None:
    """Test an authentication middleware example."""

    async def handler(request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header == "Bearer valid-token":
            return web.Response(text="Authenticated")
        return web.Response(status=401, text="Unauthorized")

    async def auth_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Add authentication header before request
        request.headers["Authorization"] = "Bearer valid-token"
        response = await handler(request)
        return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Without middleware - should fail
    async with ClientSession() as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 401

    # With middleware - should succeed
    async with ClientSession(middlewares=(auth_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Authenticated"


async def test_client_middleware_challenge_auth(aiohttp_server: AiohttpServer) -> None:
    """Test authentication middleware with challenge/response pattern like digest auth."""
    request_count = 0
    challenge_token = "challenge-123"

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1

        auth_header = request.headers.get("Authorization")

        # First request - no auth header, return challenge
        if request_count == 1 and not auth_header:
            return web.Response(
                status=401,
                headers={
                    "WWW-Authenticate": f'Custom realm="test", nonce="{challenge_token}"'
                },
            )

        # Subsequent requests - check for correct auth with challenge
        if auth_header == f'Custom response="{challenge_token}-secret"':
            return web.Response(text="Authenticated")

        assert False, "Should not reach here - invalid auth scenario"

    async def challenge_auth_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonce: Optional[str] = None
        attempted: bool = False

        while True:
            # If we have challenge data from previous attempt, add auth header
            if nonce and attempted:
                request.headers["Authorization"] = f'Custom response="{nonce}-secret"'

            response = await handler(request)

            # If we get a 401 with challenge, store it and retry
            if response.status == 401 and not attempted:
                www_auth = response.headers.get("WWW-Authenticate")
                if www_auth and "nonce=" in www_auth:
                    # Extract nonce from authentication header
                    nonce_start = www_auth.find('nonce="') + 7
                    nonce_end = www_auth.find('"', nonce_start)
                    nonce = www_auth[nonce_start:nonce_end]
                    attempted = True
                    continue
                else:
                    assert False, "Should not reach here"

            return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(challenge_auth_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Authenticated"

    # Should have made 2 requests: initial and retry with auth
    assert request_count == 2


async def test_client_middleware_multi_step_auth(aiohttp_server: AiohttpServer) -> None:
    """Test middleware with multi-step authentication flow."""
    auth_state: dict[str, int] = {}
    middleware_state: Dict[str, Optional[Union[int, str]]] = {
        "step": 0,
        "session": None,
        "challenge": None,
    }

    async def handler(request: web.Request) -> web.Response:
        client_id = request.headers.get("X-Client-ID", "unknown")
        auth_header = request.headers.get("Authorization")
        step = auth_state.get(client_id, 0)

        # Step 0: No auth, request client ID
        if step == 0 and not auth_header:
            auth_state[client_id] = 1
            return web.Response(
                status=401, headers={"X-Auth-Step": "1", "X-Session": "session-123"}
            )

        # Step 1: Has session, request credentials
        if step == 1 and auth_header == "Bearer session-123":
            auth_state[client_id] = 2
            return web.Response(
                status=401, headers={"X-Auth-Step": "2", "X-Challenge": "challenge-456"}
            )

        # Step 2: Has challenge response, authenticate
        if step == 2 and auth_header == "Bearer challenge-456-response":
            return web.Response(text="Authenticated")

        assert False, "Should not reach here - invalid multi-step auth flow"

    async def multi_step_auth_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        request.headers["X-Client-ID"] = "test-client"

        for _ in range(3):
            # Apply auth based on current state
            if middleware_state["step"] == 1 and middleware_state["session"]:
                request.headers["Authorization"] = (
                    f"Bearer {middleware_state['session']}"
                )
            elif middleware_state["step"] == 2 and middleware_state["challenge"]:
                request.headers["Authorization"] = (
                    f"Bearer {middleware_state['challenge']}-response"
                )

            response = await handler(request)

            # Handle multi-step auth flow
            if response.status == 401:
                auth_step = response.headers.get("X-Auth-Step")

                if auth_step == "1":
                    # First step: store session token
                    middleware_state["session"] = response.headers.get("X-Session")
                    middleware_state["step"] = 1
                    continue

                elif auth_step == "2":
                    # Second step: store challenge
                    middleware_state["challenge"] = response.headers.get("X-Challenge")
                    middleware_state["step"] = 2
                    continue
                else:
                    assert False, "Should not reach here"

            return response
        # This should not be reached but keeps mypy happy
        assert False, "Should not reach here"

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(multi_step_auth_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Authenticated"


async def test_client_middleware_conditional_retry(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test middleware with conditional retry based on response content."""
    request_count = 0
    token_state: Dict[str, Union[str, bool]] = {
        "token": "old-token",
        "refreshed": False,
    }

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1

        auth_token = request.headers.get("X-Auth-Token")

        if request_count == 1:
            # First request returns expired token error
            return web.json_response(
                {"error": "token_expired", "refresh_required": True}, status=401
            )

        if auth_token == "refreshed-token":
            return web.json_response({"data": "success"})

        assert False, "Should not reach here - invalid token refresh flow"

    async def token_refresh_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        for _ in range(2):
            # Add token to request
            request.headers["X-Auth-Token"] = str(token_state["token"])

            response = await handler(request)

            # Check if token needs refresh
            if response.status == 401 and not token_state["refreshed"]:
                data = await response.json()
                if data.get("error") == "token_expired" and data.get(
                    "refresh_required"
                ):
                    # Simulate token refresh
                    token_state["token"] = "refreshed-token"
                    token_state["refreshed"] = True
                    continue
                else:
                    assert False, "Should not reach here"

            return response
        # This should not be reached but keeps mypy happy
        assert False, "Should not reach here"

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    async with ClientSession(middlewares=(token_refresh_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data == {"data": "success"}

    assert request_count == 2  # Initial request + retry after refresh


async def test_build_client_middlewares_empty() -> None:
    """Test build_client_middlewares with empty middlewares."""

    async def handler(request: ClientRequest) -> NoReturn:
        """Dummy handler."""
        assert False

    # Test empty case
    result = build_client_middlewares(handler, ())
    assert result is handler  # Should return handler unchanged


async def test_client_middleware_class_based_auth(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test middleware using class-based pattern with instance state."""

    class TokenAuthMiddleware:
        """Middleware that handles token-based authentication."""

        def __init__(self, token: str) -> None:
            self.token = token
            self.request_count = 0

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            self.request_count += 1
            request.headers["Authorization"] = f"Bearer {self.token}"
            return await handler(request)

    async def handler(request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header == "Bearer test-token":
            return web.Response(text="Authenticated")
        assert False, "Should not reach here - class auth should always have token"

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create middleware instance
    auth_middleware = TokenAuthMiddleware("test-token")

    async with ClientSession(middlewares=(auth_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Authenticated"

    # Verify the middleware was called
    assert auth_middleware.request_count == 1


async def test_client_middleware_stateful_retry(aiohttp_server: AiohttpServer) -> None:
    """Test retry middleware using class with state management."""

    class RetryMiddleware:
        """Middleware that retries failed requests with backoff."""

        def __init__(self, max_retries: int = 3) -> None:
            self.max_retries = max_retries

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            retry_count = 0

            while True:
                response = await handler(request)

                if response.status >= 500 and retry_count < self.max_retries:
                    retry_count += 1
                    continue

                return response

    request_count = 0

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1

        if request_count < 3:
            return web.Response(status=503)
        return web.Response(text="Success")

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    retry_middleware = RetryMiddleware(max_retries=2)

    async with ClientSession(middlewares=(retry_middleware,)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Success"

    assert request_count == 3  # Initial + 2 retries


async def test_client_middleware_multiple_instances(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test using multiple instances of the same middleware class."""

    class HeaderMiddleware:
        """Middleware that adds a header with instance-specific value."""

        def __init__(self, header_name: str, header_value: str) -> None:
            self.header_name = header_name
            self.header_value = header_value
            self.applied = False

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            self.applied = True
            request.headers[self.header_name] = self.header_value
            return await handler(request)

    headers_received = {}

    async def handler(request: web.Request) -> web.Response:
        headers_received.update(dict(request.headers))
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create two instances with different headers
    middleware1 = HeaderMiddleware("X-Custom-1", "value1")
    middleware2 = HeaderMiddleware("X-Custom-2", "value2")

    async with ClientSession(middlewares=(middleware1, middleware2)) as session:
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200

    # Both middlewares should have been applied
    assert middleware1.applied is True
    assert middleware2.applied is True
    assert headers_received.get("X-Custom-1") == "value1"
    assert headers_received.get("X-Custom-2") == "value2"


async def test_request_middleware_overrides_session_middleware_with_empty(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that passing empty middlewares tuple to a request disables session-level middlewares."""
    session_middleware_called = False

    async def handler(request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header:
            return web.Response(text=f"Auth: {auth_header}")
        return web.Response(text="No auth")

    async def session_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal session_middleware_called
        session_middleware_called = True
        request.headers["Authorization"] = "Bearer session-token"
        response = await handler(request)
        return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create session with middleware
    async with ClientSession(middlewares=(session_middleware,)) as session:
        # First request uses session middleware
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Auth: Bearer session-token"
            assert session_middleware_called is True

        # Reset flags
        session_middleware_called = False

        # Second request explicitly disables middlewares with empty tuple
        async with session.get(server.make_url("/"), middlewares=()) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "No auth"
            assert session_middleware_called is False


async def test_request_middleware_overrides_session_middleware_with_specific(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that passing specific middlewares to a request overrides session-level middlewares."""
    session_middleware_called = False
    request_middleware_called = False

    async def handler(request: web.Request) -> web.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header:
            return web.Response(text=f"Auth: {auth_header}")
        return web.Response(text="No auth")

    async def session_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal session_middleware_called
        session_middleware_called = True
        request.headers["Authorization"] = "Bearer session-token"
        response = await handler(request)
        return response

    async def request_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal request_middleware_called
        request_middleware_called = True
        request.headers["Authorization"] = "Bearer request-token"
        response = await handler(request)
        return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create session with middleware
    async with ClientSession(middlewares=(session_middleware,)) as session:
        # First request uses session middleware
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Auth: Bearer session-token"
            assert session_middleware_called is True
            assert request_middleware_called is False

        # Reset flags
        session_middleware_called = False
        request_middleware_called = False

        # Second request uses request-specific middleware
        async with session.get(
            server.make_url("/"), middlewares=(request_middleware,)
        ) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Auth: Bearer request-token"
            assert session_middleware_called is False
            assert request_middleware_called is True


@pytest.mark.parametrize(
    "exception_class,match_text",
    [
        (ValueError, "Middleware error"),
        (ClientError, "Client error from middleware"),
        (OSError, "OS error from middleware"),
    ],
)
async def test_client_middleware_exception_closes_connection(
    aiohttp_server: AiohttpServer,
    exception_class: type[Exception],
    match_text: str,
) -> None:
    """Test that connections are closed when middleware raises an exception."""

    async def handler(request: web.Request) -> NoReturn:
        assert False, "Handler should not be reached"

    async def failing_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> NoReturn:
        # Raise exception before the handler is called
        raise exception_class(match_text)

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    # Create custom connector
    connector = TCPConnector()

    async with ClientSession(
        connector=connector, middlewares=(failing_middleware,)
    ) as session:
        # Make request that should fail in middleware
        with pytest.raises(exception_class, match=match_text):
            await session.get(server.make_url("/"))

    # Check that the connector has no active connections
    # If connections were properly closed, _conns should be empty
    assert len(connector._conns) == 0

    await connector.close()


async def test_client_middleware_blocks_connection_before_established(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can block connections before they are established."""
    blocked_hosts = {"blocked.example.com", "evil.com"}
    connection_attempts: List[str] = []

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="Reached")

    async def blocking_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Record the connection attempt
        connection_attempts.append(str(request.url))

        # Block requests to certain hosts
        if request.url.host in blocked_hosts:
            raise BlockedByMiddleware(f"Connection to {request.url.host} is blocked")

        # Allow the request to proceed
        return await handler(request)

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    connector = TCPConnector()
    async with ClientSession(
        connector=connector, middlewares=(blocking_middleware,)
    ) as session:
        # Test allowed request
        allowed_url = server.make_url("/")
        async with session.get(allowed_url) as resp:
            assert resp.status == 200
            assert await resp.text() == "Reached"

        # Test blocked request
        with pytest.raises(BlockedByMiddleware) as exc_info:
            # Use a fake URL that would fail DNS if connection was attempted
            await session.get("https://blocked.example.com/")

        assert "Connection to blocked.example.com is blocked" in str(exc_info.value)

        # Test another blocked host
        with pytest.raises(BlockedByMiddleware) as exc_info:
            await session.get("https://evil.com/path")

        assert "Connection to evil.com is blocked" in str(exc_info.value)

    # Verify that connections were attempted in the correct order
    assert len(connection_attempts) == 3
    assert allowed_url.host

    assert connection_attempts == [
        str(server.make_url("/")),
        "https://blocked.example.com/",
        "https://evil.com/path",
    ]

    # Check that no connections were leaked
    assert len(connector._conns) == 0

    await connector.close()


async def test_client_middleware_blocks_connection_without_dns_lookup(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware prevents DNS lookups for blocked hosts."""
    blocked_hosts = {"blocked.domain.tld"}
    dns_lookups_made: List[str] = []

    # Create a simple server for the allowed request
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    class TrackingResolver(ThreadedResolver):
        async def resolve(
            self,
            hostname: str,
            port: int = 0,
            family: socket.AddressFamily = socket.AF_INET,
        ) -> List[ResolveResult]:
            dns_lookups_made.append(hostname)
            return await super().resolve(hostname, port, family)

    async def blocking_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Block requests to certain hosts before DNS lookup
        if request.url.host in blocked_hosts:
            raise BlockedByMiddleware(f"Blocked by policy: {request.url.host}")

        return await handler(request)

    resolver = TrackingResolver()
    connector = TCPConnector(resolver=resolver)
    async with ClientSession(
        connector=connector, middlewares=(blocking_middleware,)
    ) as session:
        # Test blocked request to non-existent domain
        with pytest.raises(BlockedByMiddleware) as exc_info:
            await session.get("https://blocked.domain.tld/")

        assert "Blocked by policy: blocked.domain.tld" in str(exc_info.value)

        # Verify that no DNS lookup was made for the blocked domain
        assert "blocked.domain.tld" not in dns_lookups_made

        # Test allowed request to existing server - this should trigger DNS lookup
        async with session.get(f"http://localhost:{server.port}") as resp:
            assert resp.status == 200

        # Verify that DNS lookup was made for the allowed request
        # The server might use a hostname that requires DNS resolution
        assert len(dns_lookups_made) > 0

        # Make sure blocked domain is still not in DNS lookups
        assert "blocked.domain.tld" not in dns_lookups_made

    # Clean up
    await connector.close()


async def test_client_middleware_retry_reuses_connection(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that connections are reused when middleware performs retries."""
    request_count = 0

    async def handler(request: web.Request) -> web.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return web.Response(status=400)  # First request returns 400 with no body
        return web.Response(text="OK")

    class TrackingConnector(TCPConnector):
        """Connector that tracks connection attempts."""

        connection_attempts = 0

        async def _create_connection(
            self, req: ClientRequest, traces: List["Trace"], timeout: "ClientTimeout"
        ) -> ResponseHandler:
            self.connection_attempts += 1
            return await super()._create_connection(req, traces, timeout)

    class RetryOnceMiddleware:
        """Middleware that retries exactly once."""

        def __init__(self) -> None:
            self.attempt_count = 0

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            retry_count = 0
            while True:
                self.attempt_count += 1
                response = await handler(request)
                if response.status == 400 and retry_count == 0:
                    retry_count += 1
                    continue
                return response

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)

    connector = TrackingConnector()
    middleware = RetryOnceMiddleware()

    async with ClientSession(connector=connector, middlewares=(middleware,)) as session:
        # Make initial request
        async with session.get(server.make_url("/")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "OK"

    # Should have made 2 request attempts (initial + 1 retry)
    assert middleware.attempt_count == 2
    # Should have created only 1 connection (reused on retry)
    assert connector.connection_attempts == 1

    await connector.close()


async def test_middleware_uses_session_avoids_recursion_with_path_check(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can avoid infinite recursion using a path check."""
    log_collector: List[Dict[str, str]] = []

    async def log_api_handler(request: web.Request) -> web.Response:
        """Handle log API requests."""
        data: Dict[str, str] = await request.json()
        log_collector.append(data)
        return web.Response(text="OK")

    async def main_handler(request: web.Request) -> web.Response:
        """Handle main server requests."""
        return web.Response(text=f"Hello from {request.path}")

    # Create log API server
    log_app = web.Application()
    log_app.router.add_post("/log", log_api_handler)
    log_server = await aiohttp_server(log_app)

    # Create main server
    main_app = web.Application()
    main_app.router.add_get("/{path:.*}", main_handler)
    main_server = await aiohttp_server(main_app)

    async def log_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        """Log requests to external API, avoiding recursion with path check."""
        # Avoid infinite recursion by not logging requests to the /log endpoint
        if request.url.path != "/log":
            # Use the session from the request to make the logging call
            async with request.session.post(
                f"http://localhost:{log_server.port}/log",
                json={"method": str(request.method), "url": str(request.url)},
            ) as resp:
                assert resp.status == 200

        return await handler(request)

    # Create session with the middleware
    async with ClientSession(middlewares=(log_middleware,)) as session:
        # Make request to main server - should be logged
        async with session.get(main_server.make_url("/test")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Hello from /test"

        # Make direct request to log API - should NOT be logged (avoid recursion)
        async with session.post(
            log_server.make_url("/log"),
            json={"method": "DIRECT_POST", "url": "manual_test_entry"},
        ) as resp:
            assert resp.status == 200

    # Check logs
    # The first request should be logged
    # The second request (to /log) should also be logged but not the middleware's own log request
    assert len(log_collector) == 2
    assert log_collector[0]["method"] == "GET"
    assert log_collector[0]["url"] == str(main_server.make_url("/test"))
    assert log_collector[1]["method"] == "DIRECT_POST"
    assert log_collector[1]["url"] == "manual_test_entry"


async def test_middleware_uses_session_avoids_recursion_with_disabled_middleware(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can avoid infinite recursion by disabling middleware."""
    log_collector: List[Dict[str, str]] = []
    request_count = 0

    async def log_api_handler(request: web.Request) -> web.Response:
        """Handle log API requests."""
        nonlocal request_count
        request_count += 1
        data: Dict[str, str] = await request.json()
        log_collector.append(data)
        return web.Response(text="OK")

    async def main_handler(request: web.Request) -> web.Response:
        """Handle main server requests."""
        return web.Response(text=f"Hello from {request.path}")

    # Create log API server
    log_app = web.Application()
    log_app.router.add_post("/log", log_api_handler)
    log_server = await aiohttp_server(log_app)

    # Create main server
    main_app = web.Application()
    main_app.router.add_get("/{path:.*}", main_handler)
    main_server = await aiohttp_server(main_app)

    async def log_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        """Log all requests using session with disabled middleware."""
        # Use the session from the request to make the logging call
        # Disable middleware to avoid infinite recursion
        async with request.session.post(
            f"http://localhost:{log_server.port}/log",
            json={"method": str(request.method), "url": str(request.url)},
            middlewares=(),  # This prevents infinite recursion
        ) as resp:
            assert resp.status == 200

        return await handler(request)

    # Create session with the middleware
    async with ClientSession(middlewares=(log_middleware,)) as session:
        # Make request to main server - should be logged
        async with session.get(main_server.make_url("/test")) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "Hello from /test"

        # Make another request - should also be logged
        async with session.get(main_server.make_url("/another")) as resp:
            assert resp.status == 200

    # Check logs - both requests should be logged
    assert len(log_collector) == 2
    assert log_collector[0]["method"] == "GET"
    assert log_collector[0]["url"] == str(main_server.make_url("/test"))
    assert log_collector[1]["method"] == "GET"
    assert log_collector[1]["url"] == str(main_server.make_url("/another"))

    # Ensure that log requests were made without the middleware
    # (request_count equals number of logged requests, not infinite)
    assert request_count == 2


async def test_middleware_can_check_request_body(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can check request body."""
    received_bodies: List[str] = []
    received_headers: List[Dict[str, str]] = []

    async def handler(request: web.Request) -> web.Response:
        """Server handler that receives requests."""
        body = await request.text()
        received_bodies.append(body)
        received_headers.append(dict(request.headers))
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_post("/api", handler)
    app.router.add_get("/api", handler)  # Add GET handler too
    server = await aiohttp_server(app)

    class CustomAuth:
        """Middleware that follows the GitHub discussion pattern for authentication."""

        def __init__(self, secretkey: str) -> None:
            self.secretkey = secretkey

        def get_hash(self, request: ClientRequest) -> str:
            if request.body:
                data = request.body.decode("utf-8")
            else:
                data = "{}"

            # Simulate authentication hash without using real crypto
            return f"SIGNATURE-{self.secretkey}-{len(data)}-{data[:10]}"

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            request.headers["CUSTOM-AUTH"] = self.get_hash(request)
            return await handler(request)

    middleware = CustomAuth("test-secret-key")

    async with ClientSession(middlewares=(middleware,)) as session:
        # Test 1: Send JSON data with user/action
        data1 = {"user": "alice", "action": "login"}
        json_str1 = json.dumps(data1)
        async with session.post(
            server.make_url("/api"),
            data=json_str1,
            headers={"Content-Type": "application/json"},
        ) as resp:
            assert resp.status == 200

        # Test 2: Send JSON data with different fields
        data2 = {"user": "bob", "value": 42}
        json_str2 = json.dumps(data2)
        async with session.post(
            server.make_url("/api"),
            data=json_str2,
            headers={"Content-Type": "application/json"},
        ) as resp:
            assert resp.status == 200

        # Test 3: Send GET request with no body
        async with session.get(server.make_url("/api")) as resp:
            assert resp.status == 200  # GET with empty body still should validate

        # Test 4: Send plain text (non-JSON)
        text_data = "plain text body"
        async with session.post(
            server.make_url("/api"),
            data=text_data,
            headers={"Content-Type": "text/plain"},
        ) as resp:
            assert resp.status == 200

    # Verify server received the correct headers with authentication
    headers1 = received_headers[0]
    assert (
        headers1["CUSTOM-AUTH"]
        == f"SIGNATURE-test-secret-key-{len(json_str1)}-{json_str1[:10]}"
    )

    headers2 = received_headers[1]
    assert (
        headers2["CUSTOM-AUTH"]
        == f"SIGNATURE-test-secret-key-{len(json_str2)}-{json_str2[:10]}"
    )

    headers3 = received_headers[2]
    # GET request with no body should have empty JSON body
    assert headers3["CUSTOM-AUTH"] == "SIGNATURE-test-secret-key-2-{}"

    headers4 = received_headers[3]
    assert (
        headers4["CUSTOM-AUTH"]
        == f"SIGNATURE-test-secret-key-{len(text_data)}-{text_data[:10]}"
    )

    # Verify all responses were successful
    assert received_bodies[0] == json_str1
    assert received_bodies[1] == json_str2
    assert received_bodies[2] == ""  # GET request has no body
    assert received_bodies[3] == text_data


async def test_client_middleware_update_shorter_body(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can update request body using update_body method."""

    async def handler(request: web.Request) -> web.Response:
        body = await request.text()
        return web.Response(text=body)

    app = web.Application()
    app.router.add_post("/", handler)
    server = await aiohttp_server(app)

    async def update_body_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Update the request body
        await request.update_body(b"short body")
        return await handler(request)

    async with ClientSession(middlewares=(update_body_middleware,)) as session:
        async with session.post(server.make_url("/"), data=b"original body") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "short body"


async def test_client_middleware_update_longer_body(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can update request body using update_body method."""

    async def handler(request: web.Request) -> web.Response:
        body = await request.text()
        return web.Response(text=body)

    app = web.Application()
    app.router.add_post("/", handler)
    server = await aiohttp_server(app)

    async def update_body_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Update the request body
        await request.update_body(b"much much longer body")
        return await handler(request)

    async with ClientSession(middlewares=(update_body_middleware,)) as session:
        async with session.post(server.make_url("/"), data=b"original body") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "much much longer body"


async def test_client_middleware_update_string_body(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can update request body using update_body method."""

    async def handler(request: web.Request) -> web.Response:
        body = await request.text()
        return web.Response(text=body)

    app = web.Application()
    app.router.add_post("/", handler)
    server = await aiohttp_server(app)

    async def update_body_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Update the request body
        await request.update_body("this is a string")
        return await handler(request)

    async with ClientSession(middlewares=(update_body_middleware,)) as session:
        async with session.post(server.make_url("/"), data="original string") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "this is a string"


async def test_client_middleware_switch_types(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that middleware can update request body using update_body method."""

    async def handler(request: web.Request) -> web.Response:
        body = await request.text()
        return web.Response(text=body)

    app = web.Application()
    app.router.add_post("/", handler)
    server = await aiohttp_server(app)

    async def update_body_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Update the request body
        await request.update_body("now a string")
        return await handler(request)

    async with ClientSession(middlewares=(update_body_middleware,)) as session:
        async with session.post(server.make_url("/"), data=b"original bytes") as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "now a string"
