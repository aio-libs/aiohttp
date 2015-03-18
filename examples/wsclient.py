#!/usr/bin/env python3
"""websocket cmd client for wssrv.py example."""
import argparse
import signal
import sys

import asyncio
try:
    import selectors
except ImportError:
    from asyncio import selectors

import aiohttp


def start_client(loop, url):
    name = input('Please enter your name: ')

    # send request
    ws = yield from aiohttp.ws_connect(url)

    # input reader
    def stdin_callback():
        line = sys.stdin.buffer.readline().decode('utf-8')
        if not line:
            loop.stop()
        else:
            ws.send_str(name + ': ' + line)
    loop.add_reader(sys.stdin.fileno(), stdin_callback)

    @asyncio.coroutine
    def dispatch():
        while True:
            try:
                msg = yield from ws.receive()
            except aiohttp.WSServerDisconnectedError:
                # server disconnected
                break

            if msg.tp == aiohttp.MSG_TEXT:
                print(msg.data.strip())
            elif msg.tp == aiohttp.MSG_CLOSE:
                break

    yield from dispatch()


ARGS = argparse.ArgumentParser(
    description="websocket console client for wssrv.py example.")
ARGS.add_argument(
    '--host', action="store", dest='host',
    default='127.0.0.1', help='Host name')
ARGS.add_argument(
    '--port', action="store", dest='port',
    default=8080, type=int, help='Port number')

if __name__ == '__main__':
    args = ARGS.parse_args()
    if ':' in args.host:
        args.host, port = args.host.split(':', 1)
        args.port = int(port)

    url = 'http://{}:{}'.format(args.host, args.port)

    loop = asyncio.SelectorEventLoop(selectors.SelectSelector())
    asyncio.set_event_loop(loop)

    loop.add_signal_handler(signal.SIGINT, loop.stop)
    asyncio.Task(start_client(loop, url))
    loop.run_forever()
