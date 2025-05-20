#!/usr/bin/env python3
"""
Example of using digest authentication middleware with aiohttp client.

This example shows how to use the DigestAuthMiddleware from
aiohttp.client_middleware_digest_auth to authenticate with a server
that requires digest authentication with qop=auth.

In this case, it connects to httpbin.org's digest auth endpoint.
"""

import asyncio

from yarl import URL

from aiohttp import ClientSession
from aiohttp.client_middleware_digest_auth import DigestAuthMiddleware

# URLs for httpbin digest auth (qop=auth) with different algorithms
DIGEST_AUTH_SHA256_URL = URL("https://httpbin.org/digest-auth/auth/my/dog/SHA-256")
DIGEST_AUTH_MD5_URL = URL("https://httpbin.org/digest-auth/auth/my/dog/MD5")
DIGEST_AUTH_SHA512_URL = URL("https://httpbin.org/digest-auth/auth/my/dog/SHA-512")


async def main():
    # Create a DigestAuthMiddleware instance with appropriate credentials
    # Username: my
    # Password: dog
    digest_auth = DigestAuthMiddleware(login="my", password="dog")

    # Create a client session with the digest auth middleware
    async with ClientSession(middlewares=[digest_auth]) as session:
        # Test with SHA-256 algorithm
        print("\n=== Testing with SHA-256 algorithm ===\n")
        async with session.get(DIGEST_AUTH_SHA256_URL) as resp:
            print(f"Status: {resp.status}")
            print(f"Headers: {resp.headers}")

            # Parse the JSON response
            json_response = await resp.json()
            print(f"Response: {json_response}")

            # Verify authentication was successful
            if resp.status == 200:
                print("\nAuthentication successful!")
                print(f"Authenticated user: {json_response.get('user')}")
                print(f"Authentication method: {json_response.get('authenticated')}")
            else:
                print("\nAuthentication failed.")

        # Test with MD5 algorithm
        print("\n=== Testing with MD5 algorithm ===\n")
        async with session.get(DIGEST_AUTH_MD5_URL) as resp:
            print(f"Status: {resp.status}")
            print(f"Headers: {resp.headers}")

            # Parse the JSON response
            json_response = await resp.json()
            print(f"Response: {json_response}")

            # Verify authentication was successful
            if resp.status == 200:
                print("\nAuthentication successful!")
                print(f"Authenticated user: {json_response.get('user')}")
                print(f"Authentication method: {json_response.get('authenticated')}")
            else:
                print("\nAuthentication failed.")

        # Test with SHA-512 algorithm
        print("\n=== Testing with SHA-512 algorithm ===\n")
        async with session.get(DIGEST_AUTH_SHA512_URL) as resp:
            print(f"Status: {resp.status}")
            print(f"Headers: {resp.headers}")

            # Parse the JSON response
            json_response = await resp.json()
            print(f"Response: {json_response}")

            # Verify authentication was successful
            if resp.status == 200:
                print("\nAuthentication successful!")
                print(f"Authenticated user: {json_response.get('user')}")
                print(f"Authentication method: {json_response.get('authenticated')}")
            else:
                print("\nAuthentication failed.")


if __name__ == "__main__":
    asyncio.run(main())
