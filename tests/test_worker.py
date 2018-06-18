"""Tests for aiohttp/worker.py"""
import asyncio
import os
import pathlib
import socket
import ssl
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.test_utils import make_mocked_coro


base_worker = pytest.importorskip('aiohttp.worker')


try:
    import uvloop
except ImportError:
    uvloop = None


WRONG_LOG_FORMAT = '%a "%{Referrer}i" %(h)s %(l)s %s'
ACCEPTABLE_LOG_FORMAT = '%a "%{Referrer}i" %s'


# tokio event loop does not allow to override attributes
def skip_if_no_dict(loop):
    if not hasattr(loop, '__dict__'):
        pytest.skip("can not override loop attributes")


class BaseTestWorker:

    def __init__(self):
        self.servers = {}
        self.exit_code = 0
        self._notify_waiter = None
        self.cfg = mock.Mock()
        self.cfg.graceful_timeout = 100
        self.pid = 'pid'
        self.wsgi = web.Application()


class AsyncioWorker(BaseTestWorker, base_worker.GunicornWebWorker):  # type: ignore  # noqa
    pass


PARAMS = [AsyncioWorker]
if uvloop is not None:
    class UvloopWorker(BaseTestWorker, base_worker.GunicornUVLoopWebWorker):  # type: ignore  # noqa
        pass

    PARAMS.append(UvloopWorker)


@pytest.fixture(params=PARAMS)
def worker(request, loop):
    asyncio.set_event_loop(loop)
    ret = request.param()
    ret.notify = mock.Mock()
    return ret


def test_init_process(worker):
    with mock.patch('aiohttp.worker.asyncio') as m_asyncio:
        try:
            worker.init_process()
        except TypeError:
            pass

        assert m_asyncio.get_event_loop.return_value.close.called
        assert m_asyncio.new_event_loop.called
        assert m_asyncio.set_event_loop.called


def test_run(worker, loop):
    worker.log = mock.Mock()
    worker.cfg = mock.Mock()
    worker.cfg.access_log_format = ACCEPTABLE_LOG_FORMAT

    worker.loop = loop
    worker._run = make_mocked_coro(None)
    with pytest.raises(SystemExit):
        worker.run()
    assert worker._run.called
    assert loop.is_closed()


def test_run_async_factory(worker, loop):
    worker.log = mock.Mock()
    worker.cfg = mock.Mock()
    worker.cfg.access_log_format = ACCEPTABLE_LOG_FORMAT
    app = worker.wsgi

    async def make_app():
        return app
    worker.wsgi = make_app

    worker.loop = loop
    worker._run = make_mocked_coro(None)
    with pytest.raises(SystemExit):
        worker.run()
    assert worker._run.called
    assert loop.is_closed()


def test_handle_quit(worker, loop):
    worker.loop = mock.Mock()
    worker.handle_quit(object(), object())
    assert not worker.alive
    assert worker.exit_code == 0
    worker.loop.call_later.asset_called_with(
        0.1, worker._notify_waiter_done)


def test_handle_abort(worker):
    with mock.patch('aiohttp.worker.sys') as m_sys:
        worker.handle_abort(object(), object())
        assert not worker.alive
        assert worker.exit_code == 1
        m_sys.exit.assert_called_with(1)


def test__wait_next_notify(worker):
    worker.loop = mock.Mock()
    worker._notify_waiter_done = mock.Mock()
    fut = worker._wait_next_notify()

    assert worker._notify_waiter == fut
    worker.loop.call_later.assert_called_with(1.0,
                                              worker._notify_waiter_done,
                                              fut)


def test__notify_waiter_done(worker):
    worker._notify_waiter = None
    worker._notify_waiter_done()
    assert worker._notify_waiter is None

    waiter = worker._notify_waiter = mock.Mock()
    worker._notify_waiter.done.return_value = False
    worker._notify_waiter_done()

    assert worker._notify_waiter is None
    waiter.set_result.assert_called_with(True)


def test__notify_waiter_done_explicit_waiter(worker):
    worker._notify_waiter = None
    assert worker._notify_waiter is None

    waiter = worker._notify_waiter = mock.Mock()
    waiter.done.return_value = False
    waiter2 = worker._notify_waiter = mock.Mock()
    worker._notify_waiter_done(waiter)

    assert worker._notify_waiter is waiter2
    waiter.set_result.assert_called_with(True)
    assert not waiter2.set_result.called


def test_init_signals(worker):
    worker.loop = mock.Mock()
    worker.init_signals()
    assert worker.loop.add_signal_handler.called


@pytest.mark.parametrize('source,result', [
    (ACCEPTABLE_LOG_FORMAT, ACCEPTABLE_LOG_FORMAT),
    (AsyncioWorker.DEFAULT_GUNICORN_LOG_FORMAT,
     AsyncioWorker.DEFAULT_AIOHTTP_LOG_FORMAT),
])
def test__get_valid_log_format_ok(worker, source, result):
    assert result == worker._get_valid_log_format(source)


def test__get_valid_log_format_exc(worker):
    with pytest.raises(ValueError) as exc:
        worker._get_valid_log_format(WRONG_LOG_FORMAT)
    assert '%(name)s' in str(exc)


async def test__run_ok_parent_changed(worker, loop, aiohttp_unused_port):
    skip_if_no_dict(loop)

    worker.ppid = 0
    worker.alive = True
    sock = socket.socket()
    addr = ('localhost', aiohttp_unused_port())
    sock.bind(addr)
    worker.sockets = [sock]
    worker.log = mock.Mock()
    worker.loop = loop
    worker.cfg.access_log_format = ACCEPTABLE_LOG_FORMAT
    worker.cfg.max_requests = 0
    worker.cfg.is_ssl = False

    worker._runner = web.AppRunner(worker.wsgi)
    await worker._runner.setup()

    await worker._run()

    worker.notify.assert_called_with()
    worker.log.info.assert_called_with("Parent changed, shutting down: %s",
                                       worker)
    assert worker._runner.server is None


async def test__run_exc(worker, loop, aiohttp_unused_port):
    skip_if_no_dict(loop)

    worker.ppid = os.getppid()
    worker.alive = True
    sock = socket.socket()
    addr = ('localhost', aiohttp_unused_port())
    sock.bind(addr)
    worker.sockets = [sock]
    worker.log = mock.Mock()
    worker.loop = loop
    worker.cfg.access_log_format = ACCEPTABLE_LOG_FORMAT
    worker.cfg.max_requests = 0
    worker.cfg.is_ssl = False

    worker._runner = web.AppRunner(worker.wsgi)
    await worker._runner.setup()

    def raiser():
        waiter = worker._notify_waiter
        worker.alive = False
        waiter.set_exception(RuntimeError())

    loop.call_later(0.1, raiser)
    await worker._run()

    worker.notify.assert_called_with()
    assert worker._runner.server is None


async def test__run_ok_max_requests_exceeded(worker, loop,
                                             aiohttp_unused_port):
    skip_if_no_dict(loop)

    worker.ppid = os.getppid()
    worker.alive = True
    worker.servers = {}
    sock = socket.socket()
    addr = ('localhost', aiohttp_unused_port())
    sock.bind(addr)
    worker.sockets = [sock]
    worker.log = mock.Mock()
    worker.loop = loop
    worker.cfg.access_log_format = ACCEPTABLE_LOG_FORMAT
    worker.cfg.max_requests = 10
    worker.cfg.is_ssl = False

    worker._runner = web.AppRunner(worker.wsgi)
    await worker._runner.setup()
    worker._runner.server.requests_count = 30

    await worker._run()

    worker.notify.assert_called_with()
    worker.log.info.assert_called_with("Max requests, shutting down: %s",
                                       worker)

    assert worker._runner.server is None


def test__create_ssl_context_without_certs_and_ciphers(worker):
    here = pathlib.Path(__file__).parent
    worker.cfg.ssl_version = ssl.PROTOCOL_SSLv23
    worker.cfg.cert_reqs = ssl.CERT_OPTIONAL
    worker.cfg.certfile = str(here / 'sample.crt')
    worker.cfg.keyfile = str(here / 'sample.key')
    worker.cfg.ca_certs = None
    worker.cfg.ciphers = None
    crt = worker._create_ssl_context(worker.cfg)
    assert isinstance(crt, ssl.SSLContext)


def test__create_ssl_context_with_ciphers(worker):
    here = pathlib.Path(__file__).parent
    worker.cfg.ssl_version = ssl.PROTOCOL_SSLv23
    worker.cfg.cert_reqs = ssl.CERT_OPTIONAL
    worker.cfg.certfile = str(here / 'sample.crt')
    worker.cfg.keyfile = str(here / 'sample.key')
    worker.cfg.ca_certs = None
    worker.cfg.ciphers = 'PSK'
    ctx = worker._create_ssl_context(worker.cfg)
    assert isinstance(ctx, ssl.SSLContext)


def test__create_ssl_context_with_ca_certs(worker):
    here = pathlib.Path(__file__).parent
    worker.cfg.ssl_version = ssl.PROTOCOL_SSLv23
    worker.cfg.cert_reqs = ssl.CERT_OPTIONAL
    worker.cfg.certfile = str(here / 'sample.crt')
    worker.cfg.keyfile = str(here / 'sample.key')
    worker.cfg.ca_certs = str(here / 'sample.crt')
    worker.cfg.ciphers = None
    ctx = worker._create_ssl_context(worker.cfg)
    assert isinstance(ctx, ssl.SSLContext)
