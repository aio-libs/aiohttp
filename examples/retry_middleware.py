#!/usr/bin/env python3
"""
Example of using retry middleware with aiohttp client.

This example shows how to implement a middleware that automatically retries
failed requests with exponential backoff. The middleware can be configured
with custom retry statuses, maximum retries, and backoff parameters.

This example includes a test server that simulates various HTTP responses
and can return different status codes on sequential requests.
"""

import asyncio
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, List, Set, Union

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse, ClientSession, web

logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)

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
                    "Retrying request to %s (attempt %s/%s)",
                    request.url,
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
                _LOGGER.warning(
                    "Max retries (%s) exceeded for %s", self.max_retries, request.url
                )
                return response

            # Wait before retrying
            _LOGGER.debug("Waiting %ss before retry...", delay)
            await asyncio.sleep(delay)
            delay *= self.backoff_factor

        # Return the last response
        if TYPE_CHECKING:
            assert last_response is not None  # Always set since we loop at least once
        return last_response


class TestServer:
    """Test server with stateful endpoints for retry testing."""

    def __init__(self) -> None:
        self.request_counters: Dict[str, int] = {}
        self.status_sequences: Dict[str, List[int]] = {
            "eventually-ok": [500, 503, 502, 200],  # Fails 3 times, then succeeds
            "always-error": [500, 500, 500, 500],  # Always fails
            "immediate-ok": [200],  # Succeeds immediately
            "flaky": [503, 200],  # Fails once, then succeeds
        }

    async def handle_status(self, request: web.Request) -> web.Response:
        """Return the status code specified in the path."""
        status = int(request.match_info["status"])
        return web.Response(status=status, text=f"Status: {status}")

    async def handle_status_sequence(self, request: web.Request) -> web.Response:
        """Return different status codes on sequential requests."""
        path = request.path

        # Initialize counter for this path if needed
        if path not in self.request_counters:
            self.request_counters[path] = 0

        # Get the status sequence for this path
        sequence_name = request.match_info["name"]
        if sequence_name not in self.status_sequences:
            return web.Response(status=404, text="Sequence not found")

        sequence = self.status_sequences[sequence_name]

        # Get the current status based on request count
        count = self.request_counters[path]
        if count < len(sequence):
            status = sequence[count]
        else:
            # After sequence ends, always return the last status
            status = sequence[-1]

        # Increment counter for next request
        self.request_counters[path] += 1

        return web.Response(
            status=status, text=f"Request #{count + 1}: Status {status}"
        )

    async def handle_delay(self, request: web.Request) -> web.Response:
        """Delay response by specified seconds."""
        delay = float(request.match_info["delay"])
        await asyncio.sleep(delay)
        return web.json_response({"delay": delay, "message": "Response after delay"})

    async def handle_reset(self, request: web.Request) -> web.Response:
        """Reset request counters."""
        self.request_counters = {}
        return web.Response(text="Counters reset")


async def run_test_server() -> web.AppRunner:
    """Run a simple test server."""
    app = web.Application()
    server = TestServer()

    app.router.add_get("/status/{status}", server.handle_status)
    app.router.add_get("/sequence/{name}", server.handle_status_sequence)
    app.router.add_get("/delay/{delay}", server.handle_delay)
    app.router.add_post("/reset", server.handle_reset)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    return runner


async def run_tests() -> None:
    """Run all retry middleware tests."""
    # Create retry middleware with custom settings
    retry_middleware = RetryMiddleware(
        max_retries=3,
        retry_statuses=DEFAULT_RETRY_STATUSES,
        initial_delay=0.5,
        backoff_factor=2.0,
    )

    async with ClientSession(middlewares=(retry_middleware,)) as session:
        # Reset counters before tests
        await session.post("http://localhost:8080/reset")

        # Test 1: Request that succeeds immediately
        print("=== Test 1: Immediate success ===")
        async with session.get("http://localhost:8080/sequence/immediate-ok") as resp:
            text = await resp.text()
            print(f"Final status: {resp.status}")
            print(f"Response: {text}")
            print("Success - no retries needed\n")

        # Test 2: Request that eventually succeeds after retries
        print("=== Test 2: Eventually succeeds (500->503->502->200) ===")
        async with session.get("http://localhost:8080/sequence/eventually-ok") as resp:
            text = await resp.text()
            print(f"Final status: {resp.status}")
            print(f"Response: {text}")
            if resp.status == 200:
                print("Success after retries!\n")
            else:
                print("Failed after retries\n")

        # Test 3: Request that always fails
        print("=== Test 3: Always fails (500->500->500->500) ===")
        async with session.get("http://localhost:8080/sequence/always-error") as resp:
            text = await resp.text()
            print(f"Final status: {resp.status}")
            print(f"Response: {text}")
            print("Failed after exhausting all retries\n")

        # Test 4: Flaky service (fails once then succeeds)
        print("=== Test 4: Flaky service (503->200) ===")
        await session.post("http://localhost:8080/reset")  # Reset counters
        async with session.get("http://localhost:8080/sequence/flaky") as resp:
            text = await resp.text()
            print(f"Final status: {resp.status}")
            print(f"Response: {text}")
            print("Success after one retry!\n")

        # Test 5: Non-retryable status
        print("=== Test 5: Non-retryable status (404) ===")
        async with session.get("http://localhost:8080/status/404") as resp:
            print(f"Final status: {resp.status}")
            print("Failed immediately - not a retryable status\n")

        # Test 6: Delayed response
        print("=== Test 6: Testing with delay endpoint ===")
        try:
            async with session.get("http://localhost:8080/delay/0.5") as resp:
                print(f"Status: {resp.status}")
                data = await resp.json()
                print(f"Response received after delay: {data}\n")
        except asyncio.TimeoutError:
            print("Request timed out\n")


async def main() -> None:
    # Start test server
    server = await run_test_server()

    try:
        await run_tests()
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
