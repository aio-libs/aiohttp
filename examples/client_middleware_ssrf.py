"""
SSRF Protection middleware example.

This example demonstrates how to protect against Server-Side Request Forgery
(SSRF) attacks using client middleware by blocking requests to private IP addresses.

Note: This is a demonstration of the concepts. For production use, consider
additional security measures and edge cases.
"""

import asyncio
import logging
from typing import List, Tuple

from aiohttp import (
    ClientError,
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    web,
)

_LOGGER = logging.getLogger(__name__)

FAST_TIMEOUT = ClientTimeout(total=1.0)


class SSRFProtectionError(ClientError):
    """Raised when SSRF protection blocks a request."""


# ========== Test Server Implementation ==========


class SSRFTestServer:
    """Test server for demonstrating SSRF protection."""

    def __init__(self) -> None:
        """Initialize the test server."""
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up the server routes."""
        self.app.router.add_get("/public", self.public_endpoint)
        self.app.router.add_get("/local", self.local_endpoint)
        self.app.router.add_get("/malicious-redirect", self.malicious_redirect_endpoint)

    async def public_endpoint(self, request: web.Request) -> web.Response:
        """Public endpoint that should be accessible."""
        return web.json_response({"message": "Public resource accessed"})

    async def local_endpoint(self, request: web.Request) -> web.Response:
        """Local endpoint that should be blocked by SSRF protection."""
        return web.json_response({"message": "Local resource accessed - SSRF!"})

    async def malicious_redirect_endpoint(self, request: web.Request) -> web.Response:
        """Malicious endpoint that redirects to internal resource."""
        redirect_url = "http://internal.corp/steal_secrets/?upload_to=http://fake.tld"
        _LOGGER.warning("Server: Malicious redirect attempted to: %s", redirect_url)
        return web.Response(status=302, headers={"Location": redirect_url})

    async def start(self, host: str = "127.0.0.1", port: int = 8080) -> str:
        """Start the server and return its URL."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, host, port)
        await site.start()

        url = f"http://{host}:{port}"
        _LOGGER.info("Test server started at %s", url)
        return url

    async def cleanup(self) -> None:
        """Clean up server resources."""
        await self.runner.cleanup()


# ========== Client Examples ==========


async def test_basic_ssrf_protection(server_url: str) -> None:
    """Example 1: Basic SSRF protection test."""
    _LOGGER.info("=== Example 1: Basic SSRF Protection ===")

    # Define test cases
    tests: List[Tuple[str, str, bool]] = [
        # Should be allowed (test server is an exception)
        ("Test server public endpoint", f"{server_url}/public", True),
        ("Test server local endpoint", f"{server_url}/local", True),
        # Should be blocked (all items from blocked_domains)
        ("Blocked domain internal.corp", "http://internal.corp/api", False),
        ("Localhost", "http://localhost/admin", False),
        ("metadata.aws domain", "http://metadata.aws/latest", False),
        (
            "AWS metadata IP 169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            False,
        ),
        (
            "GCP metadata domain",
            "http://metadata.google.internal/computeMetadata/v1/",
            False,
        ),
        ("Blocked IP 10.0.0.1", "http://10.0.0.1/local", False),
        ("Blocked IP 10.0.0.50", "http://10.0.0.50/steal", False),
        ("Blocked IP 192.168.1.1", "http://192.168.1.1/local", False),
        ("Blocked IP 192.168.1.100", "http://192.168.1.100/config", False),
        ("Blocked IP 172.16.0.1", "http://172.16.0.1/router", False),
    ]

    async def ssrf_protection_middleware(
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Block requests to specific domains."""
        host = request.url.host

        # Blocked domains that are known to point to internal resources
        blocked_domains = {
            "internal.corp",
            "localhost",
            "metadata.aws",
            "169.254.169.254",  # AWS metadata service
            "metadata.google.internal",  # GCP metadata service
            "10.0.0.1",
            "10.0.0.50",
            "192.168.1.1",
            "192.168.1.100",
            "172.16.0.1",
        }

        # Check if domain/host is blocked
        if host and host in blocked_domains:
            error_msg = f"Request to blocked host '{host}' denied"
            _LOGGER.error(error_msg)
            raise SSRFProtectionError(error_msg)

        _LOGGER.debug("SSRF check passed for %s (host=%s)", request.url, host)
        return await handler(request)

    # Test with SSRF protection
    async with ClientSession(middlewares=(ssrf_protection_middleware,)) as session:
        for name, url, should_succeed in tests:
            _LOGGER.info("Testing %s: %s", name, url)
            try:
                async with session.get(url, timeout=FAST_TIMEOUT) as resp:
                    if should_succeed:
                        _LOGGER.info("  ✓ Allowed: status=%s", resp.status)
                    else:
                        _LOGGER.error("  ✗ FAILED: Should have been blocked!")
            except SSRFProtectionError as e:
                if not should_succeed:
                    _LOGGER.info("  ✓ Blocked: %s", e)
                else:
                    _LOGGER.error("  ✗ FAILED: Should have been allowed! %s", e)
            except Exception as e:
                _LOGGER.info("  ~ Error: %s - %s", type(e).__name__, str(e)[:50])


async def test_redirect_protection(server_url: str) -> None:
    """Example 2: Test SSRF protection against redirects."""
    _LOGGER.info("=== Example 2: Redirect Protection ===")

    # Define blocked domains that are known to resolve to private IPs
    blocked_domains = {"internal.corp", "private.local", "10.0.0.50.xip.io"}

    # Create middleware that blocks certain domains
    async def ssrf_middleware_specific_domains(
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Enhanced SSRF protection that blocks specific domains."""
        # Check if domain is in blocklist
        if request.url.host in blocked_domains:
            error_msg = f"Request to blocked domain '{request.url.host}' denied"
            _LOGGER.error(error_msg)
            raise SSRFProtectionError(error_msg)

        return await handler(request)

    async with ClientSession(
        middlewares=(ssrf_middleware_specific_domains,)
    ) as session:
        _LOGGER.info("Testing redirect from our server to internal domain...")
        _LOGGER.info("Redirect target: internal.corp (blocked domain)")

        _LOGGER.info("Testing redirect to internal.corp...")
        try:
            async with session.get(
                f"{server_url}/malicious-redirect",
                timeout=FAST_TIMEOUT,
                allow_redirects=True,
            ) as resp:
                _LOGGER.error("  ✗ FAILED: Redirect should have been blocked!")
                _LOGGER.error("  Response: %s", await resp.text())
        except SSRFProtectionError as e:
            _LOGGER.info("  ✓ Successfully blocked: %s", e)
        except Exception as e:
            _LOGGER.info("  Error: %s - %s", type(e).__name__, str(e)[:50])


async def main() -> None:
    """Run the SSRF protection demo."""
    # Start test server
    server = SSRFTestServer()
    server_url = await server.start()

    try:
        # Example 1: Basic SSRF protection
        await test_basic_ssrf_protection(server_url)

        # Example 2: Redirect protection
        await test_redirect_protection(server_url)

        _LOGGER.info("=== Demo complete! ===")
    finally:
        await server.cleanup()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    asyncio.run(main())
