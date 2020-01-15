"""Async cluster http worker for aiohttp.web"""

import argparse
import asyncio
import fcntl
import logging
import os
import signal
import socket
import sys
import time
import traceback
from importlib import import_module
from typing import MutableMapping, Optional, List

import setproctitle

from aiohttp import web
from aiohttp.web_app import Application


class AbstractWorker:
    message = 'alive'
    message_data = bytes(message, 'utf-8')
    proctitle = None

    def __init__(self, app, log: logging.Logger):
        self.app = app
        self.log = log
        if AbstractWorker.proctitle is None:
            AbstractWorker.proctitle = setproctitle.getproctitle()

    def run(self) -> Optional:
        result = asyncio.run(self._run())
        asyncio.run(self.shutdown(close_resources=False))
        return result

    async def _run(self) -> None:
        raise NotImplementedError

    async def shutdown(self, close_resources=True) -> None:
        raise NotImplementedError


class ClusteredWorker(AbstractWorker):
    def __init__(self, app, log, sock, ppid, fd, graceful_timeout=60.0):
        super().__init__(app, log)

        self._ppid = ppid
        self._fd = fd  # write socket descriptor for child process
        self._last_written_at = None  # last write timestamp into child socket
        self.sock = sock
        self.graceful_timeout = graceful_timeout

        self.runner = None

    async def _run(self) -> None:

        setproctitle.setproctitle("%s Fork process [%d]" % (self.proctitle, os.getpid()))

        self.runner = await self._run_app()

        try:
            while True:
                await asyncio.sleep(1.0)
                self._notify_parent()
        except BaseException as e:
            print(e)
            traceback.print_tb(e)
            pass

    async def shutdown(self, close_resources=True) -> None:
        if self.runner is not None:
            await self.runner.cleanup()

    async def _run_app(self) -> web.AppRunner:
        runner = web.AppRunner(self.app, logger=self.log, keepalive_timeout=15.0, access_log=None)
        await runner.setup()

        assert runner is not None
        server = runner.server
        assert server is not None

        for sock in self.sock:
            site = web.SockSite(runner, sock=sock, shutdown_timeout=self.graceful_timeout / 100 * 95)
            await site.start()

        return runner

    def _notify_parent(self):
        if self._last_written_at is None or (time.time() - self._last_written_at) > 1.0:
            self._fd.write(self.message_data)
            self._fd.flush()
            self._last_written_at = time.time()

            if self._ppid != os.getppid():
                self.log.debug("Parent changed, shutting down: %s", self)
                asyncio.get_running_loop().stop()


class WorkerWatcher(AbstractWorker):
    class Children:
        message = 'alive'

        def __init__(self, pid, pipe, fd, remove_children):
            self.pid = pid
            self.pipe = pipe
            self.fd = fd
            self.last_status_at = time.time()
            self.remove_children = remove_children

        def notified(self):
            if time.time() - self.last_status_at > 1.0:
                data = self.fd.read()
                if isinstance(data, bytes):
                    data = str(data, 'utf-8')

                if isinstance(data, str) and data.startswith(self.message):
                    self.last_status_at = time.time()

        def shutdown(self, close_resources=True):
            self.remove_children(self, close_resources)

    def __init__(self, app, log, sock: List[socket.socket], processes):
        super().__init__(app, log)

        if len(sock) == 0:
            raise RuntimeError('Expected equals or greather than 1 count of sockets, got 0.')

        self.sock = sock  # type: List[socket.socket]
        self._children_count = 0
        self._children = {}  # type: MutableMapping[int, WorkerWatcher.Children]
        self._processes = processes
        self._loop = None

    def run(self) -> None:
        worker = super().run()
        if isinstance(worker, ClusteredWorker):
            worker.run()

    async def _run(self) -> Optional[ClusteredWorker]:

        setproctitle.setproctitle("%s Main process [%d]" % (self.proctitle, os.getpid()))

        self._loop = asyncio.get_event_loop()

        try:
            while True:
                if self._children_count < self._processes:
                    worker = self._fork()
                    if isinstance(worker, ClusteredWorker):
                        return worker
                self._check_forks()
                if self._children_count >= self._processes:
                    await asyncio.sleep(1.0)
        except BaseException as e:
            print(e)
            traceback.print_tb(e)
            pass

    async def shutdown(self, close_resources=True) -> None:
        for child in list(self._children):
            self._children[child].shutdown(close_resources)

        self._children = {}

    def _fork(self) -> Optional[ClusteredWorker]:
        (pipe_read, pipe_write) = os.pipe()

        dup = map(lambda sock: sock.dup(), self.sock)
        self.sock = dup

        child_pid = os.fork()

        if child_pid == 0:
            os.close(pipe_read)

            flag = fcntl.fcntl(pipe_write, fcntl.F_GETFL)
            fcntl.fcntl(pipe_write, fcntl.F_SETFL, flag | os.O_NONBLOCK)

            return ClusteredWorker(self.app, self.log, self.sock, os.getppid(), os.fdopen(pipe_write, 'wb'))
        else:
            self.log.debug(f'Forked child with pid {child_pid}')
            os.close(pipe_write)

            flag = fcntl.fcntl(pipe_read, fcntl.F_GETFL)
            fcntl.fcntl(pipe_read, fcntl.F_SETFL, flag | os.O_NONBLOCK)

            fd_read = os.fdopen(pipe_read, 'rb')
            children = self.Children(child_pid, pipe_read, fd_read, self.remove_children)

            self._children_count += 1
            self._children[child_pid] = children
            self._loop.add_reader(fd_read, children.notified)

    def _check_forks(self):
        for child_pid in list(self._children):
            child = self._children[child_pid]
            # print("Child with pid {} and parent pid {} last checked time is {}".format(
            #     child_pid, os.getpid(), (time.time() - child.last_status_at)))
            if time.time() - child.last_status_at > 5.0:
                child.shutdown()

    def remove_children(self, children, with_shutdown=True):
        self._loop.remove_reader(children.fd)
        if not with_shutdown:
            return
        # os.close(children.pipe)
        children.fd.close()
        del self._children[children.pid]
        self._children_count -= 1
        try:
            os.kill(children.pid, signal.SIGTERM)
            child_pid, child_status = os.waitpid(children.pid, 0)
        except BaseException as e:
            pass


class AbstractSocketFactory:
    __slots__ = '__socket__'

    def __init__(self) -> None:
        self.__socket__ = None

    def create_socket(self):
        self.__socket__ = self._create_socket()

        return self

    def _create_socket(self) -> socket.socket:
        raise NotImplementedError


class TCPSocketFactory(AbstractSocketFactory):
    __slots__ = ('host', 'port', 'reuse_address')

    def __init__(self, host, port, reuse_address=True):
        super().__init__()

        self.host = host
        self.port = port
        self.reuse_address = reuse_address

    def _create_socket(self) -> socket.socket:
        if self.reuse_address is None:
            self.reuse_address = os.name == 'posix' and sys.platform != 'cygwin'
        if self.host == '':
            self.host = None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 if self.reuse_address else 0)
        sock.bind((self.host, self.port))
        sock.setblocking(False)

        return sock


class UnixSocketFactory(AbstractSocketFactory):
    __slots__ = ('reuse_address', 'path')

    def __init__(self, path, reuse_address=True):
        super().__init__()

        self.path = path
        self.reuse_address = reuse_address

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 if self.reuse_address else 0)
        if self.reuse_address and os.path.exists(self.path):
            os.unlink(self.path)
        sock.bind(self.path)
        sock.setblocking(False)

        return sock


class ClusterRunner:
    __slots__ = ('app', '__parser__', 'log', '__socket__', 'processes', 'graceful_timeout')

    def __init__(self, socket_factories: List[AbstractSocketFactory], app, child_process_num=4, graceful_timeout=60.0):
        if isinstance(app, Application):
            self.app = app
        elif asyncio.iscoroutinefunction(app):
            self.app = app()
        else:
            raise RuntimeError(
                "app should be either Application or async function returning Application, got {}".format(app))

        self.processes = child_process_num
        self.graceful_timeout = graceful_timeout
        self.log = logging.Logger(self.__class__.__name__)

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        self.log.addHandler(handler)

        self.__socket__ = list(map(lambda f: f.create_socket().__socket__, socket_factories))

    def _create_socket(self) -> socket.socket:
        """ Define this method for implement corresponding socket type of your worker """
        raise NotImplementedError

    def run(self):
        WorkerWatcher(self.app, self.log, self.__socket__, self.processes).run()


def run_cluster(app, args):
    socket_factories = []

    if args.listen_tcp:
        socket_factories.append(TCPSocketFactory(args.hostname, args.port, args.reuse_address))
    if args.listen_unix:
        socket_factories.append(UnixSocketFactory(args.path, args.reuse_address))

    ClusterRunner(socket_factories, app, args.processes, args.graceful_timeout).run()


def main(args) -> None:
    arg_parser = argparse.ArgumentParser(
        description='aiohttp.cluster Application server configuration (worker based on fork)',
        prog="aiohttp.cluster"
    )
    arg_parser.add_argument(
        "entry_func",
        help=("Callable returning the `aiohttp.web.Application` instance to "
              "run. Should be specified in the 'module:function' syntax."),
        metavar="entry-func"
    )
    arg_parser.add_argument(
        '--processes', '-p',
        help='Number of forked child processes',
        type=int, default=4
    )
    arg_parser.add_argument(
        '--graceful-timeout', '-t',
        help='Graceful shutdown timeout in seconds',
        type=float, default=60.0
    )
    arg_parser.add_argument(
        "-H", "--hostname",
        help="TCP/IP hostname to serve on (default: %(default)r)",
        default="localhost",
    )
    arg_parser.add_argument(
        "-P", "--port",
        help="TCP/IP port to serve on (default: %(default)r)",
        type=int,
        default="8080"
    )
    arg_parser.add_argument(
        "-U", "--path",
        help="Unix file system path to serve on. Specifying a path will cause "
             "hostname and port arguments to be ignored.",
    )
    arg_parser.add_argument(
        '--reuse-address',
        help='Reuse specified address on host and port if it exists and is in TIME_WAIT state',
        type=bool, default=True
    )
    arg_parser.add_argument(
        '--listen-tcp',
        help='Listen TCP address by specified hostname and port if this option is set',
        action='store_true'
    )
    arg_parser.add_argument(
        '--listen-unix',
        help='Listen unix domain address by specified path if this option is set',
        action='store_true'
    )
    args, extra_argv = arg_parser.parse_known_args(args)

    # Import logic
    mod_str, _, func_str = args.entry_func.partition(":")
    if not func_str or not mod_str:
        arg_parser.error(
            "'entry-func' not in 'module:function' syntax"
        )
    if mod_str.startswith("."):
        arg_parser.error("relative module names not supported")
    try:
        module = import_module(mod_str)
    except ImportError as ex:
        arg_parser.error("unable to import %s: %s" % (mod_str, ex))
    try:
        func = getattr(module, func_str)
    except AttributeError:
        arg_parser.error("module %r has no attribute %r" % (mod_str, func_str))
    if not args.listen_tcp and not args.listen_unix:
        arg_parser.error("You must specify an option to listen on a TCP or unix domain socket, or both")
    elif not args.path:
        arg_parser.error("You must specify a path to listen on unix domain socket")

    # Compatibility logic
    if args.listen_unix and not hasattr(socket, 'AF_UNIX'):
        arg_parser.error("file system paths not supported by your operating environment")

    logging.basicConfig(level=logging.DEBUG)

    app = func(extra_argv)
    run_cluster(app, args)
    arg_parser.exit(message="Stopped\n")


if __name__ == "__main__":  # pragma: no branch
    main(sys.argv[1:])  # pragma: no cover
