#!/usr/bin/env python3
"""
Example of combining multiple middleware with aiohttp client.

This example shows how to chain multiple middleware together to create
a powerful request pipeline. Middleware are applied in order, demonstrating
how logging, authentication, and retry logic can work together.

The order of middleware matters:
1. Logging (outermost) - logs all attempts including retries
2. Authentication - adds auth headers before retry logic
3. Retry (innermost) - retries requests on failure
"""

import asyncio
import base64
import binascii
import logging
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Set, Union

from aiohttp import (
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    hdrs,
    web,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
_LOGGER = logging.getLogger(__name__)


class LoggingMiddleware:
    """Middleware that logs request timing and response status."""

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        start_time = time.monotonic()

        # Log request
        _LOGGER.info("[REQUEST] %s %s", request.method, request.url)

        # Execute request
        response = await handler(request)

        # Log response
        duration = time.monotonic() - start_time
        _LOGGER.info(
            "[RESPONSE] %s in %.2fs - Status: %s",
            request.url.path,
            duration,
            response.status,
        )

        return response


class BasicAuthMiddleware:
    """Middleware that adds Basic Authentication to all requests."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self._auth_header = self._encode_credentials()

    def _encode_credentials(self) -> str:
        """Encode username and password to base64."""
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Add Basic Auth header to the request."""
        # Only add auth if not already present
        if hdrs.AUTHORIZATION not in request.headers:
            request.headers[hdrs.AUTHORIZATION] = self._auth_header
            _LOGGER.debug("Added Basic Auth header")

        # Proceed with the request
        return await handler(request)


DEFAULT_RETRY_STATUSES: Set[HTTPStatus] = {
    HTTPStatus.TOO_MANY_REQUESTS,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.GATEWAY_TIMEOUT,
}


class RetryMiddleware:
    """Middleware that retries failed requests with exponential backoff."""

    def __init__(
        self,
        max_retries: int = 3,
        retry_statuses: Union[Set[HTTPStatus], None] = None,
        initial_delay: float = 1.0,
        backoff_factor: float = 2.0,
    ) -> None:
        self.max_retries = max_retries
        self.retry_statuses = retry_statuses or DEFAULT_RETRY_STATUSES
        self.initial_delay = initial_delay
        self.backoff_factor = backoff_factor

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Execute request with retry logic."""
        last_response: Union[ClientResponse, None] = None
        delay = self.initial_delay

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                _LOGGER.info(
                    "Retrying request (attempt %s/%s)",
                    attempt + 1,
                    self.max_retries + 1,
                )

            # Execute the request
            response = await handler(request)
            last_response = response

            # Check if we should retry
            if response.status not in self.retry_statuses:
                return response

            # Don't retry if we've exhausted attempts
            if attempt >= self.max_retries:
                _LOGGER.warning("Max retries exceeded")
                return response

            # Wait before retrying
            _LOGGER.debug("Waiting %ss before retry...", delay)
            await asyncio.sleep(delay)
            delay *= self.backoff_factor

        if TYPE_CHECKING:
            assert last_response is not None  # Always set since we loop at least once
        return last_response


class TestServer:
    """Test server with stateful endpoints for middleware testing."""

    def __init__(self) -> None:
        self.flaky_counter = 0
        self.protected_counter = 0

    async def handle_protected(self, request: web.Request) -> web.Response:
        """Protected endpoint that requires authentication and is flaky on first attempt."""
        auth_header = request.headers.get(hdrs.AUTHORIZATION, "")

        if not auth_header.startswith("Basic "):
            return web.Response(
                status=401,
                text="Unauthorized",
                headers={hdrs.WWW_AUTHENTICATE: 'Basic realm="test"'},
            )

        # Decode the credentials
        encoded_creds = auth_header[6:]  # Remove "Basic "
        try:
            decoded = base64.b64decode(encoded_creds).decode()
            username, password = decoded.split(":", 1)
        except (ValueError, binascii.Error):
            return web.Response(
                status=401,
                text="Invalid credentials format",
                headers={hdrs.WWW_AUTHENTICATE: 'Basic realm="test"'},
            )

        # Validate credentials
        if username != "user" or password != "pass":
            return web.Response(status=401, text="Invalid credentials")

        # Fail with 500 on first attempt to test retry + auth combination
        self.protected_counter += 1
        if self.protected_counter == 1:
            return web.Response(
                status=500, text="Internal server error (first attempt)"
            )

        return web.json_response(
            {
                "message": "Access granted",
                "user": username,
                "resource": "protected data",
            }
        )

    async def handle_flaky(self, request: web.Request) -> web.Response:
        """Endpoint that fails a few times before succeeding."""
        self.flaky_counter += 1

        # Fail the first 2 requests, succeed on the 3rd
        if self.flaky_counter <= 2:
            return web.Response(
                status=503,
                text=f"Service temporarily unavailable (attempt {self.flaky_counter})",
            )

        # Reset counter and return success
        self.flaky_counter = 0
        return web.json_response(
            {
                "message": "Success after retries!",
                "data": "Important information retrieved",
            }
        )

    async def handle_always_fail(self, request: web.Request) -> web.Response:
        """Endpoint that always returns an error."""
        return web.Response(status=500, text="Internal server error")

    async def handle_status(self, request: web.Request) -> web.Response:
        """Return the status code specified in the path."""
        status = int(request.match_info["status"])
        return web.Response(status=status, text=f"Status: {status}")


async def run_test_server() -> web.AppRunner:
    """Run a test server with various endpoints."""
    app = web.Application()
    server = TestServer()

    app.router.add_get("/protected", server.handle_protected)
    app.router.add_get("/flaky", server.handle_flaky)
    app.router.add_get("/always-fail", server.handle_always_fail)
    app.router.add_get("/status/{status}", server.handle_status)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    return runner


async def run_tests() -> None:
    """Run all the middleware tests."""
    # Create middleware instances
    logging_middleware = LoggingMiddleware()
    auth_middleware = BasicAuthMiddleware("user", "pass")
    retry_middleware = RetryMiddleware(max_retries=2, initial_delay=0.5)

    # Combine middleware - order matters!
    # Applied in order: logging -> auth -> retry -> request
    async with ClientSession(
        middlewares=(logging_middleware, auth_middleware, retry_middleware)
    ) as session:

        print(
            "=== Test 1: Protected endpoint with auth (fails once, then succeeds) ==="
        )
        print("This tests retry + auth working together...")
        async with session.get("http://localhost:8080/protected") as resp:
            if resp.status == 200:
                data = await resp.json()
                print(f"Success after retry! Response: {data}")
            else:
                print(f"Failed with status: {resp.status}")

        print("\n=== Test 2: Flaky endpoint (fails twice, then succeeds) ===")
        print("Watch the logs to see retries in action...")
        async with session.get("http://localhost:8080/flaky") as resp:
            if resp.status == 200:
                data = await resp.json()
                print(f"Success after retries! Response: {data}")
            else:
                text = await resp.text()
                print(f"Failed with status {resp.status}: {text}")

        print("\n=== Test 3: Always failing endpoint ===")
        async with session.get("http://localhost:8080/always-fail") as resp:
            print(f"Final status after retries: {resp.status}")

        print("\n=== Test 4: Non-retryable status (404) ===")
        async with session.get("http://localhost:8080/status/404") as resp:
            print(f"Status: {resp.status} (no retries for 404)")

        # Test without middleware for comparison
        print("\n=== Test 5: Request without middleware ===")
        print("Making a request to protected endpoint without middleware...")
        async with session.get(
            "http://localhost:8080/protected", middlewares=()
        ) as resp:
            print(f"Status without middleware: {resp.status}")
            if resp.status == 401:
                print("Failed as expected - no auth header added")


async def main() -> None:
    # Start test server
    server = await run_test_server()

    try:
        await run_tests()

    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
