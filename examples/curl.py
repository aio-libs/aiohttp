#!/usr/bin/env python3

import asynchttp
import sys
import tulip


def curl(url):
    response = yield from asynchttp.request('GET', url)
    print(repr(response))

    data = yield from response.read()
    print(data.decode('utf-8', 'replace'))


if __name__ == '__main__':
    if '--iocp' in sys.argv:
        from tulip import events, windows_events
        sys.argv.remove('--iocp')
        el = windows_events.ProactorEventLoop()
        events.set_event_loop(el)

    loop = tulip.get_event_loop()
    loop.run_until_complete(curl(sys.argv[1]))
