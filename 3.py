import asyncio
import aiohttp
import uvloop
import time
import logging

from aiohttp import ClientSession, TCPConnector

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

urls = ["http://www.yahoo.com","http://www.bbcnews.com","http://www.cnn.com","http://www.buzzfeed.com","http://www.walmart.com","http://www.emirates.com","http://www.kayak.com","http://www.expedia.com","http://www.apple.com","http://www.youtube.com"]
bigurls = 10 * urls

def run(enable_uvloop):
    try:
        if enable_uvloop:
            loop = uvloop.new_event_loop()
        else:
            loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        start = time.time()
        conn = TCPConnector(limit=5000, use_dns_cache=True, loop=loop, verify_ssl=False)
        with ClientSession(connector=conn) as session:
            tasks = asyncio.gather(*[asyncio.ensure_future(do_request(url, session)) for url in bigurls]) # tasks to do
            results = loop.run_until_complete(tasks) # loop until done
            end = time.time()
            logger.debug('total time:')
            logger.debug(end - start)
            return results
        loop.close()
    except Exception as e:
        logger.error(e, exc_info=True)

async def do_request(url, session):
    """
    """
    try:
        async with session.get(url) as response:
            resp = await response.text()
            return resp
    except Exception as e:
        logger.error(e, exc_info=True)

#run(True)
run(False)
