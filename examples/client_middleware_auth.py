"""Example of using client middleware for authentication in production."""

import asyncio
from typing import Optional

from aiohttp import (
    ClientMiddlewareRetry,
    ClientRequest,
    ClientResponse,
    ClientSession,
    client_middleware,
)


class TokenAuthMiddleware:
    """Middleware that handles token-based authentication with automatic refresh."""

    def __init__(self, auth_url: str, username: str, password: str) -> None:
        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    async def authenticate(self, session: ClientSession) -> None:
        """Get initial authentication tokens."""
        async with session.post(
            self.auth_url, json={"username": self.username, "password": self.password}
        ) as resp:
            data = await resp.json()
            self.access_token = data["access_token"]
            self.refresh_token = data.get("refresh_token")

    async def refresh_access_token(self, session: ClientSession) -> None:
        """Refresh the access token using refresh token."""
        if not self.refresh_token:
            # No refresh token, need to re-authenticate
            await self.authenticate(session)
            return

        async with session.post(
            f"{self.auth_url}/refresh", json={"refresh_token": self.refresh_token}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                self.access_token = data["access_token"]
            else:
                # Refresh failed, re-authenticate
                await self.authenticate(session)

    @client_middleware
    async def middleware(self, request: ClientRequest, handler) -> ClientResponse:
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
            await self.refresh_access_token(request.session)
            # Retry with new token
            raise ClientMiddlewareRetry()

        return response


class DigestAuthMiddleware:
    """Middleware for HTTP Digest Authentication."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.last_challenge: Optional[dict] = None

    def parse_www_authenticate(self, header: str) -> dict:
        """Parse WWW-Authenticate header for digest parameters."""
        # Simplified parsing - in production use a proper parser
        params = {}
        parts = header.replace("Digest ", "").split(", ")
        for part in parts:
            key, value = part.split("=", 1)
            params[key] = value.strip('"')
        return params

    def calculate_response(self, challenge: dict, method: str, uri: str) -> str:
        """Calculate digest response."""
        # Simplified - real implementation needs proper digest calculation
        import hashlib

        ha1 = hashlib.md5(
            f"{self.username}:{challenge['realm']}:{self.password}".encode()
        ).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{challenge['nonce']}:{ha2}".encode()).hexdigest()
        return response

    @client_middleware
    async def middleware(self, request: ClientRequest, handler) -> ClientResponse:
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
    token_auth = TokenAuthMiddleware(
        auth_url="https://api.example.com/auth", username="user", password="pass"
    )

    async with ClientSession(middlewares=(token_auth.middleware,)) as session:
        # Initial authentication
        await token_auth.authenticate(session)

        # Make API calls - auth will be handled automatically
        async with session.get("https://api.example.com/data") as resp:
            data = await resp.json()
            print(data)

    # Digest auth example
    digest_auth = DigestAuthMiddleware(username="user", password="pass")

    async with ClientSession(middlewares=(digest_auth.middleware,)) as session:
        # Make request - digest auth will be handled automatically
        async with session.get(
            "https://httpbin.org/digest-auth/auth/user/pass"
        ) as resp:
            data = await resp.json()
            print(data)

    # Combining multiple middlewares
    async with ClientSession(
        middlewares=(token_auth.middleware, digest_auth.middleware)
    ) as session:
        # Both middlewares will be applied
        async with session.get("https://api.example.com/data") as resp:
            data = await resp.json()
            print(data)


# Per-request middleware override example
async def example_with_override() -> None:
    # Session with default auth
    session_auth = TokenAuthMiddleware(
        auth_url="https://api.example.com/auth",
        username="default_user",
        password="default_pass",
    )

    # Different auth for specific endpoints
    admin_auth = TokenAuthMiddleware(
        auth_url="https://api.example.com/auth",
        username="admin_user",
        password="admin_pass",
    )

    async with ClientSession(middlewares=(session_auth.middleware,)) as session:
        # Use session auth
        async with session.get("https://api.example.com/user/data") as resp:
            user_data = await resp.json()
            print(user_data)

        # Override with admin auth for admin endpoints
        async with session.get(
            "https://api.example.com/admin/data", middlewares=(admin_auth.middleware,)
        ) as resp:
            admin_data = await resp.json()
            print(admin_data)


if __name__ == "__main__":
    asyncio.run(main())
