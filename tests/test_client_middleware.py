"""Tests for client middleware."""

import socket
from typing import Dict, List, NoReturn, Optional, Union

import pytest

from aiohttp import (
    ClientError,
    ClientHandlerType,
    ClientMiddlewareRetry,
    ClientRequest,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    TCPConnector,
    web,
)
from aiohttp.abc import ResolveResult
from aiohttp.client_middlewares import build_client_middlewares
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
        response = await handler(request)
        if response.status == 503:
            raise ClientMiddlewareRetry()
        return response

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
    retry_count = 0

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

        assert False  # Should not reach here

    async def challenge_auth_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        nonlocal retry_count

        # If this is a retry, add auth header
        if retry_count > 0:
            # Note: In real-world usage, middleware would store challenge data
            # between retries, not use a simple counter
            request.headers["Authorization"] = (
                f'Custom response="{challenge_token}-secret"'
            )

        response = await handler(request)

        # If we get a 401 with challenge, prepare for retry
        if response.status == 401 and retry_count == 0:
            www_auth = response.headers.get("WWW-Authenticate")
            if www_auth and "nonce=" in www_auth:
                retry_count += 1
                # In a real implementation, we'd extract and store the nonce here
                raise ClientMiddlewareRetry()

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

        return web.Response(status=403, text="Forbidden")

    async def multi_step_auth_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        request.headers["X-Client-ID"] = "test-client"

        # Apply auth based on current state
        if middleware_state["step"] == 1 and middleware_state["session"]:
            request.headers["Authorization"] = f"Bearer {middleware_state['session']}"
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
                raise ClientMiddlewareRetry()

            elif auth_step == "2":
                # Second step: store challenge
                middleware_state["challenge"] = response.headers.get("X-Challenge")
                middleware_state["step"] = 2
                raise ClientMiddlewareRetry()

        return response

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

        return web.json_response({"error": "forbidden"}, status=403)

    async def token_refresh_middleware(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        # Add token to request
        request.headers["X-Auth-Token"] = str(token_state["token"])

        response = await handler(request)

        # Check if token needs refresh
        if response.status == 401 and not token_state["refreshed"]:
            data = await response.json()
            if data.get("error") == "token_expired" and data.get("refresh_required"):
                # Simulate token refresh
                token_state["token"] = "refreshed-token"
                token_state["refreshed"] = True
                raise ClientMiddlewareRetry()

        return response

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

        def __init__(self, token: str):
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
        return web.Response(status=401, text="Unauthorized")

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

        def __init__(self, max_retries: int = 3):
            self.max_retries = max_retries
            self.retry_counts: Dict[int, int] = {}  # Track retries per request

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            request_id = id(request)

            self.retry_counts.setdefault(request_id, 0)

            response = await handler(request)

            if (
                response.status >= 500
                and self.retry_counts[request_id] < self.max_retries
            ):
                self.retry_counts[request_id] += 1
                raise ClientMiddlewareRetry()

            # Clean up after successful response
            self.retry_counts.pop(request_id, None)
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

        def __init__(self, header_name: str, header_value: str):
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


async def test_client_middleware_disable_with_empty_tuple(
    aiohttp_server: AiohttpServer,
) -> None:
    """Test that passing middlewares=() to a request disables session-level middlewares."""
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

        # Second request explicitly disables middlewares
        async with session.get(server.make_url("/"), middlewares=()) as resp:
            assert resp.status == 200
            text = await resp.text()
            assert text == "No auth"
            assert session_middleware_called is False
            assert request_middleware_called is False

        # Reset flags
        session_middleware_called = False
        request_middleware_called = False

        # Third request uses request-specific middleware
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
    assert allowed_url.host and allowed_url.host in connection_attempts[0]
    assert "blocked.example.com" in connection_attempts[1]
    assert "evil.com" in connection_attempts[2]

    # Check that no connections were leaked
    assert len(connector._conns) == 0


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
            async with session.get("https://blocked.domain.tld/"):
                pass

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
    """Test that connections are reused when ClientMiddlewareRetry is raised."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="OK")

    class TrackingConnector(TCPConnector):
        """Connector that tracks connection attempts."""

        connection_attempts = 0

        async def _create_connection(
            self, req: ClientRequest, traces: List["Trace"], timeout: "ClientTimeout"
        ):
            self.connection_attempts += 1
            return await super()._create_connection(req, traces, timeout)

    class RetryOnceMiddleware:
        """Middleware that retries exactly once."""

        def __init__(self) -> None:
            self.attempt_count = 0

        async def __call__(
            self, request: ClientRequest, handler: ClientHandlerType
        ) -> ClientResponse:
            self.attempt_count += 1
            if self.attempt_count == 1:
                raise ClientMiddlewareRetry()
            return await handler(request)

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
