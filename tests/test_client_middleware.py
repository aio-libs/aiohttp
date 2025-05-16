"""Tests for client middleware."""

from typing import Dict, Optional, Union

from aiohttp import (
    ClientHandlerType,
    ClientMiddlewareRetry,
    ClientRequest,
    ClientResponse,
    ClientSession,
    web,
)
from aiohttp.client_middlewares import build_client_middlewares
from aiohttp.test_utils import TestServer


async def test_client_middleware_called(aiohttp_server: TestServer) -> None:
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


async def test_client_middleware_retry(aiohttp_server: TestServer) -> None:
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


async def test_client_middleware_per_request(aiohttp_server: TestServer) -> None:
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


async def test_multiple_client_middlewares(aiohttp_server: TestServer) -> None:
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


async def test_client_middleware_auth_example(aiohttp_server: TestServer) -> None:
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


async def test_client_middleware_challenge_auth(aiohttp_server: TestServer) -> None:
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

        return web.Response(status=401, text="Invalid auth")

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


async def test_client_middleware_multi_step_auth(aiohttp_server: TestServer) -> None:
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


async def test_client_middleware_conditional_retry(aiohttp_server: TestServer) -> None:
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
        request.headers["X-Auth-Token"] = token_state["token"]

        response = await handler(request)

        # Check if token needs refresh
        if response.status == 401 and not token_state["refreshed"]:
            try:
                data = await response.json()
                if data.get("error") == "token_expired" and data.get(
                    "refresh_required"
                ):
                    # Simulate token refresh
                    token_state["token"] = "refreshed-token"
                    token_state["refreshed"] = True
                    raise ClientMiddlewareRetry()
            except ClientMiddlewareRetry:
                raise
            except Exception:
                pass  # Not JSON or other error

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

    async def handler(request: ClientRequest) -> Dict[str, bool]:
        return {"handled": True}

    # Test empty case
    result = build_client_middlewares(handler, ())
    assert result is handler  # Should return handler unchanged


async def test_client_middleware_class_based_auth(aiohttp_server: TestServer) -> None:
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


async def test_client_middleware_stateful_retry(aiohttp_server: TestServer) -> None:
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

            if request_id not in self.retry_counts:
                self.retry_counts[request_id] = 0

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


async def test_client_middleware_multiple_instances(aiohttp_server: TestServer) -> None:
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
