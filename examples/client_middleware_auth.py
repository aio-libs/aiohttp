"""Example of using client middleware for authentication - with test server.

This example demonstrates:
1. Token-based authentication with automatic token refresh
2. HTTP Digest authentication (SIMPLIFIED - SEE WARNING)
3. Session-level middleware (authentication applied to all requests by default)
4. Middleware override (disabling session-level middleware for specific requests)
5. Token expiration and automatic retry with refresh

The example includes both a test authentication server and client code that shows
how to properly implement authentication middleware for production use cases.

WARNING: The digest authentication implementation in this example is SIMPLIFIED
and NOT suitable for production use. It lacks proper security features like:
- Complete RFC 2617 compliance
- Proper nonce validation
- Client nonce (cnonce) support
- Quality of protection (qop) handling
- Modern hash algorithms (uses MD5 which is deprecated)

For production digest auth, use a proper implementation or well-tested library.
"""

import asyncio
import hashlib
import logging
import uuid
from typing import Any, Dict, Optional, Tuple

from aiohttp import ClientHandlerType, ClientRequest, ClientResponse, ClientSession, web

_LOGGER = logging.getLogger(__name__)

# In-memory storage for tokens and users
tokens_db: Dict[str, Tuple[str, str]] = {}  # access_token -> (user, refresh)
users_db = {
    "user": "pass",
    "admin": "admin_pass",
}


# ========== Server Implementation ==========
class AuthServer:
    """Test authentication server that provides token and digest auth endpoints."""

    def __init__(self) -> None:
        self.app = web.Application()
        self._expired_tokens: set[str] = set()
        self.setup_routes()

    def setup_routes(self) -> None:
        """Setup server routes."""
        self.app.router.add_post("/auth", self.login)
        self.app.router.add_post("/auth/refresh", self.refresh_token)
        self.app.router.add_get("/api/data", self.protected_data)
        self.app.router.add_get("/api/admin/data", self.admin_data)
        self.app.router.add_get("/api/public", self.public_data)
        self.app.router.add_get("/digest-auth", self.digest_auth)
        self.app.router.add_get("/api/expire-test", self.expire_test_data)

    async def login(self, request: web.Request) -> web.Response:
        """Handle login and return tokens."""
        data: Dict[str, str] = await request.json()
        username = data.get("username")
        password = data.get("password")

        if username not in users_db or users_db[username] != password:
            return web.Response(status=401, text="Invalid credentials")

        access_token = str(uuid.uuid4())
        refresh_token = str(uuid.uuid4())
        tokens_db[access_token] = (username, refresh_token)
        return web.json_response(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        )

    async def refresh_token(self, request: web.Request) -> web.Response:
        """Handle token refresh."""
        data: Dict[str, str] = await request.json()
        refresh_token = data.get("refresh_token")

        # Find the user with this refresh token
        for access_token, (username, stored_refresh) in list(tokens_db.items()):
            if stored_refresh != refresh_token:
                continue

            # Generate new access token
            new_access_token = str(uuid.uuid4())
            tokens_db[new_access_token] = (username, refresh_token)
            # Remove old token
            del tokens_db[access_token]
            return web.json_response({"access_token": new_access_token})

        return web.Response(status=401, text="Invalid refresh token")

    async def verify_token(self, request: web.Request) -> Optional[str]:
        """Verify bearer token and return username."""
        if (auth_header := request.headers.get("Authorization", "")).startswith(
            "Bearer "
        ):
            token = auth_header.split(" ", 1)[1]
            if token in tokens_db:
                return tokens_db[token][0]
        return None

    async def protected_data(self, request: web.Request) -> web.Response:
        """Protected endpoint requiring authentication."""
        if username := await self.verify_token(request):
            return web.json_response(
                {"message": f"Hello {username}", "data": "user data"}
            )
        return web.Response(status=401, text="Unauthorized")

    async def admin_data(self, request: web.Request) -> web.Response:
        """Admin endpoint requiring admin authentication."""
        if username := await self.verify_token(request):
            if username == "admin":
                return web.json_response(
                    {"message": "Hello admin", "data": "admin data"}
                )
            return web.Response(status=403, text="Forbidden")
        return web.Response(status=401, text="Unauthorized")

    async def public_data(self, request: web.Request) -> web.Response:
        """Public endpoint not requiring authentication."""
        return web.json_response({"message": "Public data", "data": "no auth needed"})

    async def digest_auth(self, request: web.Request) -> web.Response:
        """Digest authentication endpoint.

        WARNING: This is a simplified digest auth for demonstration purposes only.
        DO NOT USE IN PRODUCTION - it does not implement proper digest authentication.
        """
        if not request.headers.get("Authorization", "").startswith("Digest "):
            # Send challenge
            nonce = str(uuid.uuid4())
            challenge = f'Digest realm="TestRealm", nonce="{nonce}", qop="auth"'
            return web.Response(status=401, headers={"WWW-Authenticate": challenge})

        # WARNING: This is NOT proper digest auth validation - for example purposes only
        # In production, you must properly validate the digest response
        return web.json_response({"authenticated": True, "user": "test"})

    async def expire_test_data(self, request: web.Request) -> web.Response:
        """Endpoint that simulates token expiration after first call."""
        # Check if this is the first request with this token
        if not (auth_header := request.headers.get("Authorization", "")).startswith(
            "Bearer "
        ):
            return web.Response(status=401, text="Unauthorized")

        token = auth_header.split(" ", 1)[1]

        # Check if we've seen this token before in expire test
        if token in self._expired_tokens:
            # This token has been marked as expired
            return web.Response(status=401, text="Token expired")

        # Verify the token is valid
        if not (username := await self.verify_token(request)):
            return web.Response(status=401, text="Unauthorized")

        # Mark token as expired for next request
        self._expired_tokens.add(token)
        return web.json_response(
            {
                "message": f"Hello {username}, token will expire after this",
                "data": "test data",
            }
        )

    def run(self) -> web.Application:
        """Return the application."""
        return self.app


# ========== Client Middleware Implementation ==========
class TokenAuthMiddleware:
    """Middleware that handles token-based authentication with automatic refresh.

    This middleware can be created before the session and have the session injected later.
    """

    def __init__(self, auth_url: str, username: str, password: str) -> None:
        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    async def authenticate(self, session: ClientSession) -> None:
        """Get initial authentication tokens."""
        async with session.post(
            self.auth_url,
            json={"username": self.username, "password": self.password},
            # Don't use middlewares here to avoid recursion
            middlewares=(),
        ) as resp:
            data: Dict[str, str] = await resp.json()
            self.access_token = data["access_token"]
            self.refresh_token = data.get("refresh_token")
            _LOGGER.info("Authenticated as %s", self.username)

    async def refresh_access_token(self, session: ClientSession) -> None:
        """Refresh the access token using refresh token."""
        if not self.refresh_token:
            # No refresh token, need to re-authenticate
            await self.authenticate(session)
            return

        async with session.post(
            f"{self.auth_url}/refresh",
            json={"refresh_token": self.refresh_token},
            # Don't use middlewares here to avoid recursion
            middlewares=(),
        ) as resp:
            if resp.status != 200:
                # Refresh failed, re-authenticate
                _LOGGER.warning("Token refresh failed, re-authenticating")
                await self.authenticate(session)
                return

            data: Dict[str, str] = await resp.json()
            self.access_token = data["access_token"]
            _LOGGER.info("Token refreshed successfully")

    async def middleware(
        self, request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        """Apply authentication to requests and handle token refresh."""
        # Skip auth endpoints
        if str(request.url).startswith(self.auth_url):
            return await handler(request)

        retry_with_refresh = False

        while True:
            # Add auth header if we have a token
            if self.access_token:
                request.headers["Authorization"] = f"Bearer {self.access_token}"

            # Make the request
            response = await handler(request)

            # Check if token expired
            if response.status == 401 and not retry_with_refresh:
                _LOGGER.info("Got 401, attempting to refresh token")
                # Try to refresh the token
                await self.refresh_access_token(request.session)
                retry_with_refresh = True
                # Retry with new token
                continue

            return response


class DigestAuthMiddleware:
    """Middleware for HTTP Digest Authentication.

    WARNING: This is a simplified implementation for demonstration purposes only.
    DO NOT USE IN PRODUCTION - it does not implement complete digest authentication.
    For production use, implement proper digest auth with:
    - Proper nonce validation
    - Client nonce (cnonce) support
    - Quality of protection (qop) handling
    - Proper response hash calculation
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.last_challenge: Optional[Dict[str, str]] = None

    def parse_www_authenticate(self, header: str) -> Dict[str, str]:
        """Parse WWW-Authenticate header for digest parameters.

        WARNING: Simplified parser - production code should handle edge cases.
        """
        # Simplified parsing - in production use a proper RFC 2617 compliant parser
        return {
            key: value.strip('"')
            for part in header.replace("Digest ", "").split(", ")
            if "=" in part
            for key, value in [part.split("=", 1)]
        }

    def calculate_response(
        self, challenge: Dict[str, str], method: str, uri: str
    ) -> str:
        """Calculate digest response."""
        ha1 = hashlib.md5(
            f"{self.username}:{challenge['realm']}:{self.password}".encode()
        ).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{challenge['nonce']}:{ha2}".encode()).hexdigest()
        return response

    async def middleware(
        self, request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        """Handle digest authentication challenges."""
        retry_with_auth = False

        while True:
            # If we have a previous challenge or retrying, add auth header
            if self.last_challenge and retry_with_auth:
                response_hash = self.calculate_response(
                    self.last_challenge, request.method, str(request.url.path)
                )
                auth_header = (
                    f'Digest username="{self.username}", '
                    f'realm="{self.last_challenge["realm"]}", '
                    f'nonce="{self.last_challenge["nonce"]}", '
                    f'uri="{request.url.path}", '
                    f'response="{response_hash}"'
                )
                request.headers["Authorization"] = auth_header

            # Make the request
            response = await handler(request)

            # Check for authentication challenge
            if response.status == 401 and not retry_with_auth:
                www_auth = response.headers.get("WWW-Authenticate", "")
                if www_auth.startswith("Digest "):
                    # Parse and store the challenge
                    self.last_challenge = self.parse_www_authenticate(www_auth)
                    _LOGGER.info("Got digest challenge, retrying with auth")
                    retry_with_auth = True
                    # Retry with authentication
                    continue

            return response


# ========== Example Usage ==========
async def run_client_examples(server_url: str) -> None:
    """Run all client middleware examples."""
    # Example with session-level middleware
    _LOGGER.info("\n=== Example 1: Session-level token auth ===")

    # Create middleware before session
    token_auth = TokenAuthMiddleware(
        auth_url=f"{server_url}/auth",
        username="user",
        password="pass",
    )

    # Create session with middleware
    async with ClientSession(middlewares=(token_auth.middleware,)) as session:
        # Inject session into middleware
        token_auth.set_session(session)

        # Initial authentication
        await token_auth.authenticate(session)

        # All requests will use auth by default
        _LOGGER.info("Making authenticated request to /api/data")
        async with session.get(f"{server_url}/api/data") as resp:
            data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Response: %s", data)

        # Override middleware for public endpoint
        _LOGGER.info("Making public request without auth")
        async with session.get(
            f"{server_url}/api/public", middlewares=()  # Disable session middleware
        ) as resp:
            public_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Public response: %s", public_data)

    # Example with session-level digest auth
    _LOGGER.info("\n=== Example 2: Session-level digest auth ===")

    # WARNING: This digest auth is simplified for demo purposes - DO NOT USE IN PRODUCTION
    digest_auth = DigestAuthMiddleware(username="user", password="pass")

    async with ClientSession(middlewares=(digest_auth.middleware,)) as session:
        _LOGGER.info("Making digest auth request")
        async with session.get(f"{server_url}/digest-auth") as resp:
            digest_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Digest auth response: %s", digest_data)

    # Example with different auth for different users
    _LOGGER.info("\n=== Example 3: Admin vs User auth ===")

    # Create admin middleware
    admin_auth = TokenAuthMiddleware(
        auth_url=f"{server_url}/auth",
        username="admin",
        password="admin_pass",
    )

    async with ClientSession(middlewares=(admin_auth.middleware,)) as admin_session:
        await admin_auth.authenticate(admin_session)

        _LOGGER.info("Making admin request")
        async with admin_session.get(f"{server_url}/api/admin/data") as resp:
            admin_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Admin response: %s", admin_data)

    # Create user middleware
    user_auth = TokenAuthMiddleware(
        auth_url=f"{server_url}/auth",
        username="user",
        password="pass",
    )

    async with ClientSession(middlewares=(user_auth.middleware,)) as user_session:
        await user_auth.authenticate(user_session)

        _LOGGER.info("Making unauthorized admin request as regular user")
        async with user_session.get(
            f"{server_url}/api/admin/data", raise_for_status=False
        ) as resp:
            _LOGGER.info("Response status: %s (should be 403)", resp.status)

    # Example with token refresh
    _LOGGER.info("\n=== Example 4: Token expiration and refresh ===")

    refresh_auth = TokenAuthMiddleware(
        auth_url=f"{server_url}/auth",
        username="user",
        password="pass",
    )

    async with ClientSession(middlewares=(refresh_auth.middleware,)) as session:
        await refresh_auth.authenticate(session)

        _LOGGER.info("Testing token expiration and refresh")
        # First request will succeed
        async with session.get(f"{server_url}/api/expire-test") as resp:
            first_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("First request: %s", first_data)

        # Second request will get 401 and trigger refresh
        async with session.get(f"{server_url}/api/expire-test") as resp:
            second_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Second request after refresh: %s", second_data)

    # Example showing both initialization patterns
    _LOGGER.info("\n=== Example 5: Two initialization patterns ===")

    # Pattern 1: Create middleware before session (useful for dependency injection)
    _LOGGER.info("Pattern 1: Two-phase initialization")
    middleware_early = TokenAuthMiddleware(
        auth_url=f"{server_url}/auth",
        username="user",
        password="pass",
    )

    async with ClientSession(middlewares=(middleware_early.middleware,)) as session:
        await middleware_early.authenticate(session)

        async with session.get(f"{server_url}/api/data") as resp:
            two_phase_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Two-phase init response: %s", two_phase_data)

    # Pattern 2: Create middleware with factory method (simpler for direct use)
    _LOGGER.info("Pattern 2: Factory method initialization")
    async with ClientSession() as session:
        middleware_factory = await TokenAuthMiddleware.create_with_session(
            auth_url=f"{server_url}/auth",
            username="user",
            password="pass",
        )
        await middleware_factory.authenticate(session)

        # Use the same session with middleware on individual requests
        async with session.get(
            f"{server_url}/api/data", middlewares=(middleware_factory.middleware,)
        ) as resp:
            factory_data: Dict[str, Any] = await resp.json()
            _LOGGER.info("Factory method response: %s", factory_data)


async def main() -> None:
    # Start the test server
    server = AuthServer()
    runner = web.AppRunner(server.run())
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8080)
    await site.start()
    _LOGGER.info("Server started at http://localhost:8080")

    try:
        await run_client_examples("http://localhost:8080")
    finally:
        await runner.cleanup()
        _LOGGER.info("Server stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    asyncio.run(main())
