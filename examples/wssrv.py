#!/usr/bin/env python3
"""Multiprocess WebSocket http chat example."""

import argparse
import os
import socket
import signal
import time
import asyncio

import aiohttp
import aiohttp.server
from aiohttp import websocket

ARGS = argparse.ArgumentParser(description="Run simple http server.")
ARGS.add_argument(
    '--host', action="store", dest='host',
    default='127.0.0.1', help='Host name')
ARGS.add_argument(
    '--port', action="store", dest='port',
    default=8080, type=int, help='Port number')
ARGS.add_argument(
    '--workers', action="store", dest='workers',
    default=2, type=int, help='Number of workers.')

WS_FILE = os.path.join(os.path.dirname(__file__), 'websocket.html')


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

    clients = None  # list of all active connections
    parent = None  # supervisor, we use it as broadcaster to all workers

    def __init__(self, *args, parent=None, clients=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent = parent
        self.clients = clients

    @asyncio.coroutine
    def handle_request(self, message, payload):
        upgrade = 'websocket' in message.headers.get('UPGRADE', '').lower()

        if upgrade:
            # websocket handshake
            status, headers, parser, writer, protocol = websocket.do_handshake(
                message.method, message.headers, self.transport)

            resp = aiohttp.Response(
                self.writer, status, http_version=message.version)
            resp.add_headers(*headers)
            resp.send_headers()

            # install websocket parser
            dataqueue = self.reader.set_parser(parser)

            # notify everybody
            print('{}: Someone joined.'.format(os.getpid()))
            for wsc in self.clients:
                wsc.send(b'Someone joined.')
            self.clients.append(writer)
            self.parent.send(b'Someone joined.')

            # chat dispatcher
            while True:
                try:
                    msg = yield from dataqueue.read()
                except:
                    # client dropped connection
                    break

                if msg.tp == websocket.MSG_PING:
                    writer.pong()

                elif msg.tp == websocket.MSG_TEXT:
                    data = msg.data.strip()
                    print('{}: {}'.format(os.getpid(), data))
                    for wsc in self.clients:
                        if wsc is not writer:
                            wsc.send(data.encode())
                    self.parent.send(data)

                elif msg.tp == websocket.MSG_CLOSE:
                    break

            # notify everybody
            print('{}: Someone disconnected.'.format(os.getpid()))
            self.parent.send(b'Someone disconnected.')
            self.clients.remove(writer)
            for wsc in self.clients:
                wsc.send(b'Someone disconnected.')

        else:
            # send html page with js chat
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version)
            response.add_header('Transfer-Encoding', 'chunked')
            response.add_header('Content-type', 'text/html')
            response.send_headers()

            try:
                with open(WS_FILE, 'rb') as fp:
                    chunk = fp.read(8192)
                    while chunk:
                        if not response.write(chunk):
                            break
                        chunk = fp.read(8192)
            except OSError:
                response.write(b'Cannot open')

            yield from response.write_eof()
            if response.keep_alive():
                self.keep_alive(True)


class ChildProcess:

    def __init__(self, up_read, down_write, args, sock):
        self.up_read = up_read
        self.down_write = down_write
        self.args = args
        self.sock = sock
        self.clients = []

    def start(self):
        # start server
        self.loop = loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def stop():
            self.loop.stop()
            os._exit(0)
        loop.add_signal_handler(signal.SIGINT, stop)

        # heartbeat
        asyncio.Task(self.heartbeat())

        asyncio.get_event_loop().run_forever()
        os._exit(0)

    @asyncio.coroutine
    def start_server(self, writer):
        socks = yield from self.loop.create_server(
            lambda: HttpRequestHandler(
                debug=True, keep_alive=75,
                parent=writer, clients=self.clients),
            sock=self.sock)
        print('Starting srv worker process {} on {}'.format(
            os.getpid(), socks.sockets[0].getsockname()))

    @asyncio.coroutine
    def heartbeat(self):
        # setup pipes
        read_transport, read_proto = yield from self.loop.connect_read_pipe(
            aiohttp.StreamProtocol, os.fdopen(self.up_read, 'rb'))
        write_transport, _ = yield from self.loop.connect_write_pipe(
            aiohttp.StreamProtocol, os.fdopen(self.down_write, 'wb'))

        reader = read_proto.reader.set_parser(websocket.WebSocketParser)
        writer = websocket.WebSocketWriter(write_transport)

        asyncio.Task(self.start_server(writer))

        while True:
            try:
                msg = yield from reader.read()
            except:
                print('Supervisor is dead, {} stopping...'.format(os.getpid()))
                self.loop.stop()
                break

            if msg.tp == websocket.MSG_PING:
                writer.pong()
            elif msg.tp == websocket.MSG_CLOSE:
                break
            elif msg.tp == websocket.MSG_TEXT:  # broadcast message
                for wsc in self.clients:
                    wsc.send(msg.data.strip().encode())

        read_transport.close()
        write_transport.close()


class Worker:

    _started = False

    def __init__(self, sv, loop, args, sock):
        self.sv = sv
        self.loop = loop
        self.args = args
        self.sock = sock
        self.start()

    def start(self):
        assert not self._started
        self._started = True

        up_read, up_write = os.pipe()
        down_read, down_write = os.pipe()
        args, sock = self.args, self.sock

        pid = os.fork()
        if pid:
            # parent
            os.close(up_read)
            os.close(down_write)
            asyncio.async(self.connect(pid, up_write, down_read))
        else:
            # child
            os.close(up_write)
            os.close(down_read)

            # cleanup after fork
            asyncio.set_event_loop(None)

            # setup process
            process = ChildProcess(up_read, down_write, args, sock)
            process.start()

    @asyncio.coroutine
    def heartbeat(self, writer):
        while True:
            yield from asyncio.sleep(15)

            if (time.monotonic() - self.ping) < 30:
                writer.ping()
            else:
                print('Restart unresponsive worker process: {}'.format(
                    self.pid))
                self.kill()
                self.start()
                return

    @asyncio.coroutine
    def chat(self, reader):
        while True:
            try:
                msg = yield from reader.read()
            except:
                print('Restart unresponsive worker process: {}'.format(
                    self.pid))
                self.kill()
                self.start()
                return

            if msg.tp == websocket.MSG_PONG:
                self.ping = time.monotonic()

            elif msg.tp == websocket.MSG_TEXT:  # broadcast to all workers
                for worker in self.sv.workers:
                    if self.pid != worker.pid:
                        worker.writer.send(msg.data)

    @asyncio.coroutine
    def connect(self, pid, up_write, down_read):
        # setup pipes
        read_transport, proto = yield from self.loop.connect_read_pipe(
            aiohttp.StreamProtocol, os.fdopen(down_read, 'rb'))
        write_transport, _ = yield from self.loop.connect_write_pipe(
            aiohttp.StreamProtocol, os.fdopen(up_write, 'wb'))

        # websocket protocol
        reader = proto.reader.set_parser(websocket.WebSocketParser)
        writer = websocket.WebSocketWriter(write_transport)

        # store info
        self.pid = pid
        self.ping = time.monotonic()
        self.writer = writer
        self.rtransport = read_transport
        self.wtransport = write_transport
        self.chat_task = asyncio.async(self.chat(reader))
        self.heartbeat_task = asyncio.async(self.heartbeat(writer))

    def kill(self):
        self._started = False
        self.chat_task.cancel()
        self.heartbeat_task.cancel()
        self.rtransport.close()
        self.wtransport.close()
        os.kill(self.pid, signal.SIGTERM)


class Supervisor:

    def __init__(self, args):
        self.loop = asyncio.get_event_loop()
        self.args = args
        self.workers = []

    def start(self):
        # bind socket
        sock = self.sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.args.host, self.args.port))
        sock.listen(1024)
        sock.setblocking(False)

        # start processes
        for idx in range(self.args.workers):
            self.workers.append(Worker(self, self.loop, self.args, sock))

        self.loop.add_signal_handler(signal.SIGINT, lambda: self.loop.stop())
        self.loop.run_forever()


def main():
    args = ARGS.parse_args()
    if ':' in args.host:
        args.host, port = args.host.split(':', 1)
        args.port = int(port)

    supervisor = Supervisor(args)
    supervisor.start()


if __name__ == '__main__':
    main()
