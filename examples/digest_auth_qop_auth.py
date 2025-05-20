#!/usr/bin/env python3
"""
Example of using digest authentication middleware with aiohttp client.

This example shows how to use the DigestAuthMiddleware from
aiohttp.client_middleware_digest_auth to authenticate with a server
that requires digest authentication with different qop options.

In this case, it connects to httpbin.org's digest auth endpoint.
"""

import asyncio

from yarl import URL

from aiohttp import ClientSession
from aiohttp.client_middleware_digest_auth import DigestAuthMiddleware

# Define QOP options available
QOP_OPTIONS = ["auth", "auth-int"]

# Algorithms supported by httpbin.org
ALGORITHMS = ["MD5", "SHA-256", "SHA-512"]

# Username and password for testing
USERNAME = "my"
PASSWORD = "dog"


async def main() -> None:
    # Create a DigestAuthMiddleware instance with appropriate credentials
    digest_auth = DigestAuthMiddleware(login=USERNAME, password=PASSWORD)

    # Create a client session with the digest auth middleware
    async with ClientSession(middlewares=(digest_auth,)) as session:
        # Test with each QOP option
        for qop in QOP_OPTIONS:
            print(f"\n\n=== Testing with qop={qop} ===\n")

            # Test with each algorithm
            for algorithm in ALGORITHMS:
                url = URL(
                    f"https://httpbin.org/digest-auth/{qop}/{USERNAME}/{PASSWORD}/{algorithm}"
                )
                print(f"\n--- Testing with {algorithm} algorithm ---\n")

                try:
                    async with session.get(url) as resp:
                        print(f"Status: {resp.status}")
                        print(f"Headers: {resp.headers}")

                        # Parse the JSON response
                        json_response = await resp.json()
                        print(f"Response: {json_response}")

                        # Verify authentication was successful
                        if resp.status == 200:
                            print("\nAuthentication successful!")
                            print(f"Authenticated user: {json_response.get('user')}")
                            print(
                                f"Authentication method: {json_response.get('authenticated')}"
                            )
                        else:
                            print("\nAuthentication failed.")
                except Exception as e:
                    print(f"Error occurred: {e}")


if __name__ == "__main__":
    asyncio.run(main())
