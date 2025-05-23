.. currentmodule:: aiohttp

.. _aiohttp-client-middleware-cookbook:

Client Middleware Cookbook
==========================

This cookbook provides practical examples of implementing client middleware for common use cases.

.. note::

   All examples in this cookbook are also available as complete, runnable scripts in the
   ``examples/`` directory of the aiohttp repository. Look for files named ``*_middleware.py``.

.. _cookbook-basic-auth-middleware:

Basic Authentication Middleware
-------------------------------

Basic authentication is a simple authentication scheme built into the HTTP protocol.
Here's a middleware that automatically adds Basic Auth headers to all requests:

.. code-block:: python

    import base64
    from aiohttp import ClientRequest, ClientResponse, ClientHandlerType, hdrs

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
            handler: ClientHandlerType
        ) -> ClientResponse:
            """Add Basic Auth header to the request."""
            # Only add auth if not already present
            if hdrs.AUTHORIZATION not in request.headers:
                request.headers[hdrs.AUTHORIZATION] = self._auth_header

            # Proceed with the request
            return await handler(request)

Usage example:

.. code-block:: python

    import aiohttp
    import asyncio
    import logging

    _LOGGER = logging.getLogger(__name__)

    async def main():
        # Create middleware instance
        auth_middleware = BasicAuthMiddleware("user", "pass")

        # Use middleware in session
        async with aiohttp.ClientSession(middlewares=(auth_middleware,)) as session:
            async with session.get("https://httpbin.org/basic-auth/user/pass") as resp:
                _LOGGER.debug("Status: %s", resp.status)
                data = await resp.json()
                _LOGGER.debug("Response: %s", data)

    asyncio.run(main())

.. _cookbook-retry-middleware:

Simple Retry Middleware
-----------------------

A retry middleware that automatically retries failed requests with exponential backoff:

.. code-block:: python

    import asyncio
    import logging
    from http import HTTPStatus
    from typing import Union, Set
    from aiohttp import ClientRequest, ClientResponse, ClientHandlerType

    _LOGGER = logging.getLogger(__name__)

    DEFAULT_RETRY_STATUSES = {
        HTTPStatus.TOO_MANY_REQUESTS,
        HTTPStatus.INTERNAL_SERVER_ERROR,
        HTTPStatus.BAD_GATEWAY,
        HTTPStatus.SERVICE_UNAVAILABLE,
        HTTPStatus.GATEWAY_TIMEOUT
    }

    class RetryMiddleware:
        """Middleware that retries failed requests with exponential backoff."""

        def __init__(
            self,
            max_retries: int = 3,
            retry_statuses: Union[Set[int], None] = None,
            initial_delay: float = 1.0,
            backoff_factor: float = 2.0
        ) -> None:
            self.max_retries = max_retries
            self.retry_statuses = retry_statuses or DEFAULT_RETRY_STATUSES
            self.initial_delay = initial_delay
            self.backoff_factor = backoff_factor

        async def __call__(
            self,
            request: ClientRequest,
            handler: ClientHandlerType
        ) -> ClientResponse:
            """Execute request with retry logic."""
            last_response = None
            delay = self.initial_delay

            for attempt in range(self.max_retries + 1):
                if attempt > 0:
                    _LOGGER.info(
                        "Retrying request to %s (attempt %s/%s)",
                        request.url,
                        attempt + 1,
                        self.max_retries + 1
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
                        "Max retries (%s) exceeded for %s",
                        self.max_retries,
                        request.url
                    )
                    return response

                # Wait before retrying
                _LOGGER.debug("Waiting %ss before retry...", delay)
                await asyncio.sleep(delay)
                delay *= self.backoff_factor

            # Return the last response
            return last_response

Usage example:

.. code-block:: python

    import aiohttp
    import asyncio
    import logging
    from http import HTTPStatus

    _LOGGER = logging.getLogger(__name__)

    RETRY_STATUSES = {
        HTTPStatus.TOO_MANY_REQUESTS,
        HTTPStatus.INTERNAL_SERVER_ERROR,
        HTTPStatus.BAD_GATEWAY,
        HTTPStatus.SERVICE_UNAVAILABLE,
        HTTPStatus.GATEWAY_TIMEOUT
    }

    async def main():
        # Create retry middleware with custom settings
        retry_middleware = RetryMiddleware(
            max_retries=3,
            retry_statuses=RETRY_STATUSES,
            initial_delay=0.5,
            backoff_factor=2.0
        )

        async with aiohttp.ClientSession(middlewares=(retry_middleware,)) as session:
            # This will automatically retry on server errors
            async with session.get("https://httpbin.org/status/500") as resp:
                _LOGGER.debug("Final status: %s", resp.status)

    asyncio.run(main())

.. _cookbook-combining-middleware:

Combining Multiple Middleware
-----------------------------

You can combine multiple middleware to create powerful request pipelines:

.. code-block:: python

    import time
    import logging
    from aiohttp import ClientRequest, ClientResponse, ClientHandlerType

    _LOGGER = logging.getLogger(__name__)

    class LoggingMiddleware:
        """Middleware that logs request timing and response status."""

        async def __call__(
            self,
            request: ClientRequest,
            handler: ClientHandlerType
        ) -> ClientResponse:
            start_time = time.monotonic()

            # Log request
            _LOGGER.debug("[REQUEST] %s %s", request.method, request.url)

            # Execute request
            response = await handler(request)

            # Log response
            duration = time.monotonic() - start_time
            _LOGGER.debug("[RESPONSE] %s in %.2fs", response.status, duration)

            return response

    # Combine multiple middleware
    async def main():
        # Middleware are applied in order: logging -> auth -> retry -> request
        logging_middleware = LoggingMiddleware()
        auth_middleware = BasicAuthMiddleware("user", "pass")
        retry_middleware = RetryMiddleware(max_retries=2)

        async with aiohttp.ClientSession(
            middlewares=(logging_middleware, auth_middleware, retry_middleware)
        ) as session:
            async with session.get("https://httpbin.org/basic-auth/user/pass") as resp:
                text = await resp.text()
                _LOGGER.debug("Response text: %s", text)

.. _cookbook-token-refresh-middleware:

Token Refresh Middleware
------------------------

A more advanced example showing JWT token refresh:

.. code-block:: python

    import asyncio
    import time
    from http import HTTPStatus
    from typing import Union
    from aiohttp import ClientRequest, ClientResponse, ClientHandlerType, hdrs

    class TokenRefreshMiddleware:
        """Middleware that handles JWT token refresh automatically."""

        def __init__(self, token_endpoint: str, refresh_token: str) -> None:
            self.token_endpoint = token_endpoint
            self.refresh_token = refresh_token
            self.access_token: Union[str, None] = None
            self.token_expires_at: Union[float, None] = None
            self._refresh_lock = asyncio.Lock()

        async def _refresh_access_token(self, session) -> str:
            """Refresh the access token using the refresh token."""
            async with self._refresh_lock:
                # Check if another coroutine already refreshed the token
                if self.token_expires_at and time.time() < self.token_expires_at:
                    return self.access_token

                # Make refresh request without middleware to avoid recursion
                async with session.post(
                    self.token_endpoint,
                    json={"refresh_token": self.refresh_token},
                    middlewares=()  # Disable middleware for this request
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()

                    if "access_token" not in data:
                        raise ValueError("No access_token in refresh response")

                    self.access_token = data["access_token"]
                    # Token expires in 1 hour for demo, refresh 5 min early
                    expires_in = data.get("expires_in", 3600)
                    self.token_expires_at = time.time() + expires_in - 300
                    return self.access_token

        async def __call__(
            self,
            request: ClientRequest,
            handler: ClientHandlerType
        ) -> ClientResponse:
            """Add auth token to request, refreshing if needed."""
            # Skip token for refresh endpoint
            if str(request.url).endswith('/token/refresh'):
                return await handler(request)

            # Refresh token if needed
            if not self.access_token or (
                self.token_expires_at and time.time() >= self.token_expires_at
            ):
                await self._refresh_access_token(request.session)

            # Add token to request
            request.headers[hdrs.AUTHORIZATION] = f"Bearer {self.access_token}"

            # Execute request
            response = await handler(request)

            # If we get 401, try refreshing token once
            if response.status == HTTPStatus.UNAUTHORIZED:
                await self._refresh_access_token(request.session)
                request.headers[hdrs.AUTHORIZATION] = f"Bearer {self.access_token}"
                response = await handler(request)

            return response

Best Practices
--------------

1. **Keep middleware focused**: Each middleware should have a single responsibility.

2. **Order matters**: Middleware execute in the order they're listed. Place logging first,
   authentication before retry, etc.

3. **Avoid infinite recursion**: When making HTTP requests inside middleware, either:

   - Use ``middlewares=()`` to disable middleware for internal requests
   - Check the request URL/host to skip middleware for specific endpoints
   - Use a separate session for internal requests

4. **Handle errors gracefully**: Don't let middleware errors break the request flow unless
   absolutely necessary.

5. **Use bounded loops**: Always use ``for`` loops with a maximum iteration count instead
   of unbounded ``while`` loops to prevent infinite retries.

6. **Consider performance**: Each middleware adds overhead. For simple cases like adding
   static headers, consider using session or request parameters instead.

7. **Test thoroughly**: Middleware can affect all requests in subtle ways. Test edge cases
   like network errors, timeouts, and concurrent requests.

See Also
--------

- :ref:`aiohttp-client-middleware` - Core middleware documentation
- :ref:`aiohttp-client-advanced` - Advanced client usage
- :class:`DigestAuthMiddleware` - Built-in digest authentication middleware
