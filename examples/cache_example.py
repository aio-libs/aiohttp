"""
Example of caching using aiocache package. To run it you will need a Redis
instance running in localhost:6379.
Running this example you will see that the first call lasts 3 seconds and
the rest are instant because the value is retrieved from Redis.
If you want more info about the package check
https://github.com/argaen/aiocache
"""

import asyncio
import aiocache
import logging

from aiohttp.web import json_response
from aiocache import RedisCache, cached
from aiocache.serializers import JsonSerializer

logger = logging.getLogger(__name__)

aiocache.settings.set_defaults(
    cache="aiocache.RedisCache",
    namespace="test"
)


@cached(key="my_custom_key", namespace="test", serializer=JsonSerializer())
async def fetch():
    logger.info("Expensive has been called")
    await asyncio.sleep(3)
    return {"test": True}


async def main(loop):
    logger.info("Received GET /")
    return json_response(await fetch())


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(loop))
    loop.run_until_complete(main(loop))
    loop.run_until_complete(RedisCache().delete("my_custom_key"))
