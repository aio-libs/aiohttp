#!/usr/bin/env python3

import aiohttp
import sys
import asyncio


def curl(url):
    response = yield from aiohttp.request('GET', url)
    print(repr(response))

    chunk = yield from response.content.read()
    print('Downloaded: %s' % len(chunk))

    response.close()


if __name__ == '__main__':
    if '--iocp' in sys.argv:
        from asyncio import events, windows_events
        sys.argv.remove('--iocp')
        el = windows_events.ProactorEventLoop()
        events.set_event_loop(el)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(curl(sys.argv[1]))
