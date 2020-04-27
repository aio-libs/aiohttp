import asyncio
import time
from datetime import datetime

import aiohttp


async def _resource_warning(recwarn, ssl_ctx, client_ssl_ctx):
    timeout = 3 * 60

    request_interval = 60
    request_increase = 30
    next_request = 0

    async def handler_coro(_request):
        return aiohttp.web.Response(text='Test TLS response')
    http_server = aiohttp.test_utils.RawTestServer(handler_coro, ssl=ssl_ctx)
    await http_server.start_server()

    url = http_server.make_url('/')

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=client_ssl_ctx),
    ) as client:

        end = time.time() + timeout
        while True:
            now = time.time()
            if now > end:
                break

            if now > next_request:
                async with client.get(url) as resp:
                    status = resp.status
                    await resp.text()

                request_interval += request_increase
                next_request = now + request_interval
                print(f'{datetime.now()} | '
                      f'Status: {status}, next request in {request_interval}s')

            await asyncio.sleep(5)

            assert not any('unclosed transport' in
                           str(w.message) for w in recwarn)

        recwarn.clear()


def test_resource_warning(recwarn, ssl_ctx, client_ssl_ctx):
    # the future has to be run like this because with the pytest async runner
    # the warnings appear only after the test
    loop = asyncio.new_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(_resource_warning(recwarn, ssl_ctx, client_ssl_ctx))
    loop.close()
