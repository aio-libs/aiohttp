import aiohttp
import asyncio


@asyncio.coroutine
def go(session):
    print('Query http://httpbin.org/basic-auth/andrew/password')
    resp = yield from session.get(
        'http://httpbin.org/basic-auth/andrew/password')
    print(resp.status)
    try:
        body = yield from resp.text()
        print(body)
    finally:
        yield from resp.release()


loop = asyncio.get_event_loop()
session = aiohttp.ClientSession(auth=aiohttp.BasicAuth('andrew',
                                                       'password'),
                                loop=loop)
loop.run_until_complete(go(session))
session.close()

# run loop iteration for actual session closing
loop.stop()
loop.run_forever()
loop.close()
