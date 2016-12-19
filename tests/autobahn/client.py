#!/usr/bin/env python3

import asyncio

import aiohttp


def client(loop, url, name):
    ws = yield from aiohttp.ws_connect(url + '/getCaseCount')
    num_tests = int((yield from ws.receive()).data)
    print('running %d cases' % num_tests)
    yield from ws.close()

    for i in range(1, num_tests + 1):
        print('running test case:', i)
        text_url = url + '/runCase?case=%d&agent=%s' % (i, name)
        ws = yield from aiohttp.ws_connect(text_url)
        while True:
            msg = yield from ws.receive()

            if msg.type == aiohttp.MsgType.text:
                ws.send_str(msg.data)
            elif msg.type == aiohttp.MsgType.binary:
                ws.send_bytes(msg.data)
            elif msg.type == aiohttp.MsgType.close:
                yield from ws.close()
                break
            else:
                break

    url = url + '/updateReports?agent=%s' % name
    ws = yield from aiohttp.ws_connect(url)
    yield from ws.close()


def run(loop, url, name):
    try:
        yield from client(loop, url, name)
    except:
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(run(loop, 'http://localhost:9001', 'aiohttp'))
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
