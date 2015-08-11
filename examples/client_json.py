import aiohttp
import asyncio


@asyncio.coroutine
def go(session):
    print('Query http://httpbin.org/get')
    resp = yield from session.get(
        'http://httpbin.org/get')
    print(resp.status)
    try:
        data = yield from resp.json()
        print(data)
    finally:
        yield from resp.release()


loop = asyncio.get_event_loop()
session = aiohttp.ClientSession(loop=loop)
loop.run_until_complete(go(session))
session.close()

# run loop iteration for actual session closing
loop.stop()
loop.run_forever()
loop.close()
