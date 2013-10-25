#!/usr/bin/env python3
"""websocket cmd client for wssrv.py example."""
import argparse
import base64
import hashlib
import os
import signal
import sys

import asyncio
import asyncio.selectors

import aiohttp
from aiohttp import websocket

WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def start_client(loop, url):
    name = input('Please enter your name: ').encode()

    sec_key = base64.b64encode(os.urandom(16))

    # send request
    response = yield from aiohttp.request(
        'get', url,
        headers={
            'UPGRADE': 'WebSocket',
            'CONNECTION': 'Upgrade',
            'SEC-WEBSOCKET-VERSION': '13',
            'SEC-WEBSOCKET-KEY': sec_key.decode(),
        }, timeout=1.0)

    # websocket handshake
    if response.status != 101:
        raise ValueError("Handshake error: Invalid response status")
    if response.get('upgrade', '').lower() != 'websocket':
        raise ValueError("Handshake error - Invalid upgrade header")
    if response.get('connection', '').lower() != 'upgrade':
        raise ValueError("Handshake error - Invalid connection header")

    key = response.get('sec-websocket-accept', '').encode()
    match = base64.b64encode(hashlib.sha1(sec_key + WS_KEY).digest())
    if key != match:
        raise ValueError("Handshake error - Invalid challenge response")

    # switch to websocket protocol
    stream = response.stream.set_parser(websocket.WebSocketParser)
    writer = websocket.WebSocketWriter(response.transport)

    # input reader
    def stdin_callback():
        line = sys.stdin.buffer.readline()
        if not line:
            loop.stop()
        else:
            writer.send(name + b': ' + line)
    loop.add_reader(sys.stdin.fileno(), stdin_callback)

    @asyncio.coroutine
    def dispatch():
        while True:
            try:
                msg = yield from stream.read()
            except aiohttp.EofStream:
                # server disconnected
                break

            if msg.tp == websocket.MSG_PING:
                writer.pong()
            elif msg.tp == websocket.MSG_TEXT:
                print(msg.data.strip())
            elif msg.tp == websocket.MSG_CLOSE:
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

    loop = asyncio.SelectorEventLoop(asyncio.selectors.SelectSelector())
    asyncio.set_event_loop(loop)

    loop.add_signal_handler(signal.SIGINT, loop.stop)
    asyncio.Task(start_client(loop, url))
    loop.run_forever()
