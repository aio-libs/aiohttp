"""Example of using client middleware for authentication in production."""

import asyncio
import logging
from typing import Dict, Optional

from aiohttp import (
    ClientHandlerType,
    ClientMiddlewareRetry,
    ClientRequest,
    ClientResponse,
    ClientSession,
)

_LOGGER = logging.getLogger(__name__)


class TokenAuthMiddleware:
    """Middleware that handles token-based authentication with automatic refresh."""

    def __init__(
        self, auth_url: str, username: str, password: str, session: ClientSession
    ) -> None:
        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.session = session
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    async def authenticate(self) -> None:
        """Get initial authentication tokens."""
        async with self.session.post(
            self.auth_url,
            json={"username": self.username, "password": self.password},
            # Don't use middlewares here to avoid recursion
            middlewares=(),
        ) as resp:
            data = await resp.json()
            self.access_token = data["access_token"]
            self.refresh_token = data.get("refresh_token")

    async def refresh_access_token(self) -> None:
        """Refresh the access token using refresh token."""
        if not self.refresh_token:
            # No refresh token, need to re-authenticate
            await self.authenticate()
            return

        async with self.session.post(
            f"{self.auth_url}/refresh",
            json={"refresh_token": self.refresh_token},
            # Don't use middlewares here to avoid recursion
            middlewares=(),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                self.access_token = data["access_token"]
            else:
                # Refresh failed, re-authenticate
                await self.authenticate()

    async def middleware(
        self, request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        """Apply authentication to requests and handle token refresh."""
        # Skip auth endpoints
        if str(request.url).startswith(self.auth_url):
            return await handler(request)

        # Add auth header if we have a token
        if self.access_token:
            request.headers["Authorization"] = f"Bearer {self.access_token}"

        # Make the request
        response = await handler(request)

        # Check if token expired
        if response.status == 401:
            # Try to refresh the token
            await self.refresh_access_token()
            # Retry with new token
            raise ClientMiddlewareRetry()

        return response


class DigestAuthMiddleware:
    """Middleware for HTTP Digest Authentication."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.last_challenge: Optional[Dict[str, str]] = None

    def parse_www_authenticate(self, header: str) -> Dict[str, str]:
        """Parse WWW-Authenticate header for digest parameters."""
        # Simplified parsing - in production use a proper parser
        params = {}
        parts = header.replace("Digest ", "").split(", ")
        for part in parts:
            key, value = part.split("=", 1)
            params[key] = value.strip('"')
        return params

    def calculate_response(
        self, challenge: Dict[str, str], method: str, uri: str
    ) -> str:
        """Calculate digest response."""
        # Simplified - real implementation needs proper digest calculation
        import hashlib

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
        # If we have a previous challenge, add auth header
        if self.last_challenge:
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
        if response.status == 401:
            www_auth = response.headers.get("WWW-Authenticate", "")
            if www_auth.startswith("Digest "):
                # Parse and store the challenge
                self.last_challenge = self.parse_www_authenticate(www_auth)
                # Retry with authentication
                raise ClientMiddlewareRetry()

        return response


# Example usage
async def main() -> None:
    # Token-based auth example
    async with ClientSession() as session:
        # Create token auth middleware with the session
        token_auth = TokenAuthMiddleware(
            auth_url="https://api.example.com/auth",
            username="user",
            password="pass",
            session=session,
        )

        # Initial authentication
        await token_auth.authenticate()

        # Make API calls with middleware applied to specific requests
        async with session.get(
            "https://api.example.com/data", middlewares=(token_auth.middleware,)
        ) as resp:
            data = await resp.json()
            _LOGGER.debug("Received data: %s", data)

    # Digest auth example
    digest_auth = DigestAuthMiddleware(username="user", password="pass")

    async with ClientSession() as session:
        # Make request with digest auth middleware
        async with session.get(
            "https://httpbin.org/digest-auth/auth/user/pass",
            middlewares=(digest_auth.middleware,),
        ) as resp:
            data = await resp.json()
            _LOGGER.debug("Digest auth response: %s", data)

    # Combining multiple middlewares on a per-request basis
    async with ClientSession() as session:
        # Both middlewares will be applied to this request
        async with session.get(
            "https://api.example.com/data",
            middlewares=(token_auth.middleware, digest_auth.middleware),
        ) as resp:
            data = await resp.json()
            _LOGGER.debug("Combined middleware response: %s", data)


# Per-request middleware override example
async def example_with_override() -> None:
    async with ClientSession() as session:
        # Create different auth middlewares for different endpoints
        session_auth = TokenAuthMiddleware(
            auth_url="https://api.example.com/auth",
            username="default_user",
            password="default_pass",
            session=session,
        )

        # Different auth for specific endpoints
        admin_auth = TokenAuthMiddleware(
            auth_url="https://api.example.com/auth",
            username="admin_user",
            password="admin_pass",
            session=session,
        )

        # Authenticate both before using
        await session_auth.authenticate()
        await admin_auth.authenticate()

        # Use default auth for user endpoints
        async with session.get(
            "https://api.example.com/user/data", middlewares=(session_auth.middleware,)
        ) as resp:
            user_data = await resp.json()
            _LOGGER.debug("User data: %s", user_data)

        # Use admin auth for admin endpoints
        async with session.get(
            "https://api.example.com/admin/data", middlewares=(admin_auth.middleware,)
        ) as resp:
            admin_data = await resp.json()
            _LOGGER.debug("Admin data: %s", admin_data)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())
