#!/usr/bin/env python3
"""
Example of using basic authentication middleware with aiohttp client.

This example shows how to implement a middleware that automatically adds
Basic Authentication headers to all requests. The middleware encodes the
username and password in base64 format as required by the HTTP Basic Auth
specification.

This example includes a test server that validates basic auth credentials.
"""

import asyncio
import base64
import binascii
import logging

from aiohttp import (
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    hdrs,
    web,
)

logging.basicConfig(level=logging.DEBUG)
_LOGGER = logging.getLogger(__name__)


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

        # Proceed with the request
        return await handler(request)


class TestServer:
    """Test server for basic auth endpoints."""

    async def handle_basic_auth(self, request: web.Request) -> web.Response:
        """Handle basic auth validation."""
        # Get expected credentials from path
        expected_user = request.match_info["user"]
        expected_pass = request.match_info["pass"]

        # Check if Authorization header is present
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
        if username != expected_user or password != expected_pass:
            return web.Response(
                status=401,
                text="Invalid username or password",
                headers={hdrs.WWW_AUTHENTICATE: 'Basic realm="test"'},
            )

        return web.json_response({"authenticated": True, "user": username})

    async def handle_protected_resource(self, request: web.Request) -> web.Response:
        """A protected resource that requires any valid auth."""
        auth_header = request.headers.get(hdrs.AUTHORIZATION, "")

        if not auth_header.startswith("Basic "):
            return web.Response(
                status=401,
                text="Authentication required",
                headers={hdrs.WWW_AUTHENTICATE: 'Basic realm="protected"'},
            )

        return web.json_response(
            {
                "message": "Access granted to protected resource",
                "auth_provided": True,
            }
        )


async def run_test_server() -> web.AppRunner:
    """Run a simple test server with basic auth endpoints."""
    app = web.Application()
    server = TestServer()

    app.router.add_get("/basic-auth/{user}/{pass}", server.handle_basic_auth)
    app.router.add_get("/protected", server.handle_protected_resource)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    return runner


async def run_tests() -> None:
    """Run all basic auth middleware tests."""
    # Create middleware instance
    auth_middleware = BasicAuthMiddleware("user", "pass")

    # Use middleware in session
    async with ClientSession(middlewares=(auth_middleware,)) as session:
        # Test 1: Correct credentials endpoint
        print("=== Test 1: Correct credentials ===")
        async with session.get("http://localhost:8080/basic-auth/user/pass") as resp:
            _LOGGER.info("Status: %s", resp.status)

            if resp.status == 200:
                data = await resp.json()
                _LOGGER.info("Response: %s", data)
                print("Authentication successful!")
                print(f"Authenticated: {data.get('authenticated')}")
                print(f"User: {data.get('user')}")
            else:
                print("Authentication failed!")
                print(f"Status: {resp.status}")
                text = await resp.text()
                print(f"Response: {text}")

        # Test 2: Wrong credentials endpoint
        print("\n=== Test 2: Wrong credentials endpoint ===")
        async with session.get("http://localhost:8080/basic-auth/other/secret") as resp:
            if resp.status == 401:
                print("Authentication failed as expected (wrong credentials)")
                text = await resp.text()
                print(f"Response: {text}")
            else:
                print(f"Unexpected status: {resp.status}")

        # Test 3: Protected resource
        print("\n=== Test 3: Access protected resource ===")
        async with session.get("http://localhost:8080/protected") as resp:
            if resp.status == 200:
                data = await resp.json()
                print("Successfully accessed protected resource!")
                print(f"Response: {data}")
            else:
                print(f"Failed to access protected resource: {resp.status}")


async def main() -> None:
    # Start test server
    server = await run_test_server()

    try:
        await run_tests()
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
