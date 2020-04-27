import asyncio
import time
from datetime import datetime

import aiohttp


async def _resource_warning(recwarn):
    timeout = 3 * 60

    request_interval = 30
    request_increase = 15
    next_request = 0

    async with aiohttp.ClientSession() as client:

        end = time.time() + timeout
        while True:
            now = time.time()
            if now > end:
                break

            if now > next_request:
                async with client.get('https://heise.de') as resp:
                    status = resp.status
                    await resp.text()

                request_interval += request_increase
                next_request = now + request_interval
                print(f'{datetime.now()} | '
                      f'Status: {status}, next request in {request_interval}s')

            await asyncio.sleep(5)

            for warn in recwarn:
                assert 'unclosed transport' not in str(warn.message)


def test_resource_warning(recwarn):
    # the future has to be run like this, with the pytest async runner
    # the warnings appear only after the test
    loop = asyncio.new_event_loop()
    loop.run_until_complete(_resource_warning(recwarn))
    loop.close()
