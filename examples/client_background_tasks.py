#!/usr/bin/env python3
"""
Background Task Exception Handling
===================================

Demonstrates proper exception handling for background HTTP requests.
"""

import asyncio
import logging

import aiohttp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def unsafe_pattern():
    """Fire-and-forget without exception handling (unsafe)."""
    async with aiohttp.ClientSession() as session:
        # This will fail, but exception only logged to event loop
        asyncio.create_task(session.get("http://invalid-nonexistent-domain-12345.com"))
        logger.info("Task spawned, continuing without waiting...")


async def safe_pattern_callback():
    """Fire-and-forget with callback exception handling (safe)."""

    def handle_result(task: asyncio.Task) -> None:
        try:
            resp = task.result()
            logger.info(f"Background request completed with status {resp.status}")
            resp.release()  # Critical: release connection
        except aiohttp.ClientError as e:
            logger.error(f"Background request failed: {e}")

    async with aiohttp.ClientSession() as session:
        task = asyncio.create_task(session.get("http://httpbin.org/status/500"))
        task.add_done_callback(handle_result)
        await asyncio.sleep(2)  # Wait for task to complete


async def safe_pattern_gather():
    """Multiple background tasks using asyncio.gather()."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.get("http://httpbin.org/status/200"),
            session.get("http://httpbin.org/status/500"),
            session.get("http://invalid-domain-12345.com"),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} failed: {result}")
            else:
                logger.info(f"Task {i} succeeded: {result.status}")
                result.release()  # Critical: release connection


async def main():
    logger.info("=== UNSAFE PATTERN ===")
    await unsafe_pattern()
    await asyncio.sleep(3)  # Wait to see exception logged

    logger.info("\n=== SAFE PATTERN (CALLBACK) ===")
    await safe_pattern_callback()

    logger.info("\n=== SAFE PATTERN (GATHER) ===")
    await safe_pattern_gather()


if __name__ == "__main__":
    asyncio.run(main())
