import aiohttp
import asyncio
import time

async def fetch(session, url):
    async with session.get(url,timeout=5) as response:
        return await response.text()

async def main():
    async with aiohttp.ClientSession() as session:
        async with session.get('http://python.org',timeout=5) as response:
            print(await response.text())

async def test():
    print(loop.time())
    time.sleep(8)
    print(loop.time())
    
loop = asyncio.get_event_loop()
loop.create_task(main())
loop.create_task(test())
loop.run_forever()
