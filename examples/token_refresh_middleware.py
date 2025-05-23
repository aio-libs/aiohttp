#!/usr/bin/env python3
"""
Example of using token refresh middleware with aiohttp client.

This example shows how to implement a middleware that handles JWT token
refresh automatically. The middleware:
- Adds bearer tokens to requests
- Detects when tokens are expired
- Automatically refreshes tokens when needed
- Handles concurrent requests during token refresh

This example includes a test server that simulates a JWT auth system.
Note: This is a simplified example for demonstration purposes.
In production, use proper JWT libraries and secure token storage.
"""

import asyncio
import hashlib
import json
import logging
import secrets
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Coroutine, Dict, List, Union

from aiohttp import (
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    hdrs,
    web,
)

logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)


class TokenRefreshMiddleware:
    """Middleware that handles JWT token refresh automatically."""

    def __init__(self, token_endpoint: str, refresh_token: str) -> None:
        self.token_endpoint = token_endpoint
        self.refresh_token = refresh_token
        self.access_token: Union[str, None] = None
        self.token_expires_at: Union[float, None] = None
        self._refresh_lock = asyncio.Lock()

    async def _refresh_access_token(self, session: ClientSession) -> str:
        """Refresh the access token using the refresh token."""
        async with self._refresh_lock:
            # Check if another coroutine already refreshed the token
            if (
                self.token_expires_at
                and time.time() < self.token_expires_at
                and self.access_token
            ):
                _LOGGER.debug("Token already refreshed by another request")
                return self.access_token

            _LOGGER.info("Refreshing access token...")

            # Make refresh request without middleware to avoid recursion
            async with session.post(
                self.token_endpoint,
                json={"refresh_token": self.refresh_token},
                middlewares=(),  # Disable middleware for this request
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

                if "access_token" not in data:
                    raise ValueError("No access_token in refresh response")

                self.access_token = data["access_token"]
                # Token expires in 5 minutes for demo, refresh 30 seconds early
                expires_in = data.get("expires_in", 300)
                self.token_expires_at = time.time() + expires_in - 30

                _LOGGER.info(
                    "Token refreshed successfully, expires in %s seconds", expires_in
                )
                if TYPE_CHECKING:
                    assert self.access_token is not None  # Just assigned above
                return self.access_token

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Add auth token to request, refreshing if needed."""
        # Skip token for refresh endpoint to avoid recursion
        if str(request.url).endswith("/token/refresh"):
            return await handler(request)

        # Refresh token if needed
        if not self.access_token or (
            self.token_expires_at and time.time() >= self.token_expires_at
        ):
            await self._refresh_access_token(request.session)

        # Add token to request
        request.headers[hdrs.AUTHORIZATION] = f"Bearer {self.access_token}"
        _LOGGER.debug("Added Bearer token to request")

        # Execute request
        response = await handler(request)

        # If we get 401, try refreshing token once
        if response.status == HTTPStatus.UNAUTHORIZED:
            _LOGGER.info("Got 401, attempting token refresh...")
            await self._refresh_access_token(request.session)
            request.headers[hdrs.AUTHORIZATION] = f"Bearer {self.access_token}"
            response = await handler(request)

        return response


class TestServer:
    """Test server with JWT-like token authentication."""

    def __init__(self) -> None:
        self.tokens_db: Dict[str, Dict[str, Union[str, float]]] = {}
        self.refresh_tokens_db: Dict[str, Dict[str, Union[str, float]]] = {
            # Hash of refresh token -> user data
            hashlib.sha256(b"demo_refresh_token_12345").hexdigest(): {
                "user_id": "user123",
                "username": "testuser",
                "issued_at": time.time(),
            }
        }

    def generate_access_token(self) -> str:
        """Generate a secure random access token."""
        return secrets.token_urlsafe(32)

    async def _process_token_refresh(self, data: Dict[str, str]) -> web.Response:
        """Process the token refresh request."""
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            return web.json_response({"error": "refresh_token required"}, status=400)

        # Hash the refresh token to look it up
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        if refresh_token_hash not in self.refresh_tokens_db:
            return web.json_response({"error": "Invalid refresh token"}, status=401)

        user_data = self.refresh_tokens_db[refresh_token_hash]

        # Generate new access token
        access_token = self.generate_access_token()
        expires_in = 300  # 5 minutes for demo

        # Store the access token with expiry
        token_hash = hashlib.sha256(access_token.encode()).hexdigest()
        self.tokens_db[token_hash] = {
            "user_id": user_data["user_id"],
            "username": user_data["username"],
            "expires_at": time.time() + expires_in,
            "issued_at": time.time(),
        }

        # Clean up expired tokens periodically
        current_time = time.time()
        self.tokens_db = {
            k: v
            for k, v in self.tokens_db.items()
            if isinstance(v["expires_at"], float) and v["expires_at"] > current_time
        }

        return web.json_response(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
            }
        )

    async def handle_token_refresh(self, request: web.Request) -> web.Response:
        """Handle token refresh requests."""
        try:
            data = await request.json()
            return await self._process_token_refresh(data)
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid request"}, status=400)

    async def verify_bearer_token(
        self, request: web.Request
    ) -> Union[Dict[str, Union[str, float]], None]:
        """Verify bearer token and return user data if valid."""
        auth_header = request.headers.get(hdrs.AUTHORIZATION, "")

        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]  # Remove "Bearer "
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Check if token exists and is not expired
        if token_hash in self.tokens_db:
            token_data = self.tokens_db[token_hash]
            if (
                isinstance(token_data["expires_at"], float)
                and token_data["expires_at"] > time.time()
            ):
                return token_data

        return None

    async def handle_protected_resource(self, request: web.Request) -> web.Response:
        """Protected endpoint that requires valid bearer token."""
        user_data = await self.verify_bearer_token(request)

        if not user_data:
            return web.json_response({"error": "Invalid or expired token"}, status=401)

        return web.json_response(
            {
                "message": "Access granted to protected resource",
                "user": user_data["username"],
                "data": "Secret information",
            }
        )

    async def handle_user_info(self, request: web.Request) -> web.Response:
        """Another protected endpoint."""
        user_data = await self.verify_bearer_token(request)

        if not user_data:
            return web.json_response({"error": "Invalid or expired token"}, status=401)

        return web.json_response(
            {
                "user_id": user_data["user_id"],
                "username": user_data["username"],
                "email": f"{user_data['username']}@example.com",
                "roles": ["user", "admin"],
            }
        )


async def run_test_server() -> web.AppRunner:
    """Run a test server with JWT auth endpoints."""
    test_server = TestServer()
    app = web.Application()
    app.router.add_post("/token/refresh", test_server.handle_token_refresh)
    app.router.add_get("/api/protected", test_server.handle_protected_resource)
    app.router.add_get("/api/user", test_server.handle_user_info)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    return runner


async def run_tests() -> None:
    """Run all token refresh middleware tests."""
    # Create token refresh middleware
    # In a real app, this refresh token would be securely stored
    token_middleware = TokenRefreshMiddleware(
        token_endpoint="http://localhost:8080/token/refresh",
        refresh_token="demo_refresh_token_12345",
    )

    async with ClientSession(middlewares=(token_middleware,)) as session:
        print("=== Test 1: First request (will trigger token refresh) ===")
        async with session.get("http://localhost:8080/api/protected") as resp:
            if resp.status == 200:
                data = await resp.json()
                print(f"Success! Response: {data}")
            else:
                print(f"Failed with status: {resp.status}")

        print("\n=== Test 2: Second request (uses cached token) ===")
        async with session.get("http://localhost:8080/api/user") as resp:
            if resp.status == 200:
                data = await resp.json()
                print(f"User info: {data}")
            else:
                print(f"Failed with status: {resp.status}")

        print("\n=== Test 3: Multiple concurrent requests ===")
        print("(Should only refresh token once)")
        coros: List[Coroutine[Any, Any, ClientResponse]] = []
        for i in range(3):
            coro = session.get("http://localhost:8080/api/protected")
            coros.append(coro)

        responses = await asyncio.gather(*coros)
        for i, resp in enumerate(responses):
            async with resp:
                if resp.status == 200:
                    print(f"Request {i + 1}: Success")
                else:
                    print(f"Request {i + 1}: Failed with {resp.status}")

        print("\n=== Test 4: Simulate token expiry ===")
        # For demo purposes, force token expiry
        token_middleware.token_expires_at = time.time() - 1

        print("Token expired, next request should trigger refresh...")
        async with session.get("http://localhost:8080/api/protected") as resp:
            if resp.status == 200:
                data = await resp.json()
                print(f"Success after token refresh! Response: {data}")
            else:
                print(f"Failed with status: {resp.status}")

        print("\n=== Test 5: Request without middleware (no auth) ===")
        # Make a request without any middleware to show the difference
        async with session.get(
            "http://localhost:8080/api/protected",
            middlewares=(),  # Bypass all middleware for this request
        ) as resp:
            print(f"Status: {resp.status}")
            if resp.status == 401:
                error = await resp.json()
                print(f"Failed as expected without auth: {error}")


async def main() -> None:
    # Start test server
    server = await run_test_server()

    try:
        await run_tests()
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
