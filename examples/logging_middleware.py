#!/usr/bin/env python3
"""
Example of using logging middleware with aiohttp client.

This example shows how to implement a middleware that logs request timing
and response status. This is useful for debugging, monitoring, and
understanding the flow of HTTP requests in your application.

This example includes a test server with various endpoints.
"""

import asyncio
import json
import logging
import time
from typing import Any, Coroutine, List

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse, ClientSession, web

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
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
        if request.headers:
            _LOGGER.debug("[REQUEST HEADERS] %s", request.headers)

        # Execute request
        response = await handler(request)

        # Log response
        duration = time.monotonic() - start_time
        _LOGGER.info(
            "[RESPONSE] %s %s - Status: %s - Duration: %.3fs",
            request.method,
            request.url,
            response.status,
            duration,
        )
        _LOGGER.debug("[RESPONSE HEADERS] %s", response.headers)

        return response


class TestServer:
    """Test server for logging middleware demo."""

    async def handle_hello(self, request: web.Request) -> web.Response:
        """Simple hello endpoint."""
        name = request.match_info.get("name", "World")
        return web.json_response({"message": f"Hello, {name}!"})

    async def handle_slow(self, request: web.Request) -> web.Response:
        """Endpoint that simulates slow response."""
        delay = float(request.match_info.get("delay", 1))
        await asyncio.sleep(delay)
        return web.json_response({"message": "Slow response completed", "delay": delay})

    async def handle_error(self, request: web.Request) -> web.Response:
        """Endpoint that returns an error."""
        status = int(request.match_info.get("status", 500))
        return web.Response(status=status, text=f"Error response with status {status}")

    async def handle_json_data(self, request: web.Request) -> web.Response:
        """Endpoint that echoes JSON data."""
        try:
            data = await request.json()
            return web.json_response({"echo": data, "received_at": time.time()})
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)


async def run_test_server() -> web.AppRunner:
    """Run a simple test server."""
    app = web.Application()
    server = TestServer()

    app.router.add_get("/hello", server.handle_hello)
    app.router.add_get("/hello/{name}", server.handle_hello)
    app.router.add_get("/slow/{delay}", server.handle_slow)
    app.router.add_get("/error/{status}", server.handle_error)
    app.router.add_post("/echo", server.handle_json_data)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    return runner


async def run_tests() -> None:
    """Run all the middleware tests."""
    # Create logging middleware
    logging_middleware = LoggingMiddleware()

    # Use middleware in session
    async with ClientSession(middlewares=(logging_middleware,)) as session:
        # Test 1: Simple GET request
        print("\n=== Test 1: Simple GET request ===")
        async with session.get("http://localhost:8080/hello") as resp:
            data = await resp.json()
            print(f"Response: {data}")

        # Test 2: GET with parameter
        print("\n=== Test 2: GET with parameter ===")
        async with session.get("http://localhost:8080/hello/Alice") as resp:
            data = await resp.json()
            print(f"Response: {data}")

        # Test 3: Slow request
        print("\n=== Test 3: Slow request (2 seconds) ===")
        async with session.get("http://localhost:8080/slow/2") as resp:
            data = await resp.json()
            print(f"Response: {data}")

        # Test 4: Error response
        print("\n=== Test 4: Error response ===")
        async with session.get("http://localhost:8080/error/404") as resp:
            text = await resp.text()
            print(f"Response: {text}")

        # Test 5: POST with JSON data
        print("\n=== Test 5: POST with JSON data ===")
        payload = {"name": "Bob", "age": 30, "city": "New York"}
        async with session.post("http://localhost:8080/echo", json=payload) as resp:
            data = await resp.json()
            print(f"Response: {data}")

        # Test 6: Multiple concurrent requests
        print("\n=== Test 6: Multiple concurrent requests ===")
        coros: List[Coroutine[Any, Any, ClientResponse]] = []
        for i in range(3):
            coro = session.get(f"http://localhost:8080/hello/User{i}")
            coros.append(coro)

        responses = await asyncio.gather(*coros)
        for i, resp in enumerate(responses):
            async with resp:
                data = await resp.json()
                print(f"Concurrent request {i}: {data}")


async def main() -> None:
    # Start test server
    server = await run_test_server()

    try:
        await run_tests()

    finally:
        # Cleanup server
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
