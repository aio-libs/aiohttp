import asyncio
import contextlib
import tempfile

import pytest
from py import path

from aiohttp.web import Application

from .test_utils import unused_port as _unused_port
from .test_utils import (RawTestServer, TestClient, TestServer,
                         loop_context, setup_test_loop, teardown_test_loop)

try:
    import uvloop
except:
    uvloop = None


def pytest_addoption(parser):
    parser.addoption('--fast', action='store_true', default=False,
                     help='run tests faster by disabling extra checks')
    parser.addoption('--with-uvloop-only', action='store_true', default=False,
                     help='run tests with uvloop only if available')
    parser.addoption('--without-uvloop', action='store_true', default=False,
                     help='run tests without uvloop')
    parser.addoption('--enable-loop-debug', action='store_true', default=False,
                     help='enable event loop debug mode')


@pytest.fixture
def fast(request):
    """ --fast config option """
    return request.config.getoption('--fast')


@contextlib.contextmanager
def _passthrough_loop_context(loop, fast=False):
    if loop:
        # loop already exists, pass it straight through
        yield loop
    else:
        # this shadows loop_context's standard behavior
        loop = setup_test_loop()
        yield loop
        teardown_test_loop(loop, fast=fast)


def pytest_pycollect_makeitem(collector, name, obj):
    """
    Fix pytest collecting for coroutines.
    """
    if collector.funcnamefilter(name) and asyncio.iscoroutinefunction(obj):
        return list(collector._genfunctions(name, obj))


def pytest_pyfunc_call(pyfuncitem):
    """
    Run coroutines in an event loop instead of a normal function call.
    """
    fast = pyfuncitem.config.getoption("--fast")
    if asyncio.iscoroutinefunction(pyfuncitem.function):
        existing_loop = pyfuncitem.funcargs.get('loop', None)
        with _passthrough_loop_context(existing_loop, fast=fast) as _loop:
            testargs = {arg: pyfuncitem.funcargs[arg]
                        for arg in pyfuncitem._fixtureinfo.argnames}

            task = _loop.create_task(pyfuncitem.obj(**testargs))
            _loop.run_until_complete(task)

        return True


def pytest_configure(config):
    fast = config.getoption('--fast')
    uvloop_only = config.getoption('--with-uvloop-only')

    without_uvloop = False
    if fast:
        without_uvloop = True

    if config.getoption('--without-uvloop'):
        without_uvloop = True

    LOOP_FACTORIES.clear()
    if uvloop_only and uvloop is not None:
        LOOP_FACTORIES.append(uvloop.new_event_loop)
    elif without_uvloop:
        LOOP_FACTORIES.append(asyncio.new_event_loop)
    else:
        LOOP_FACTORIES.append(asyncio.new_event_loop)
        if uvloop is not None:
            LOOP_FACTORIES.append(uvloop.new_event_loop)

    asyncio.set_event_loop(None)


LOOP_FACTORIES = []


@pytest.yield_fixture(params=LOOP_FACTORIES)
def loop(request):
    """Return an instance of the event loop."""
    fast = request.config.getoption('--fast')
    debug = request.config.getoption('--enable-loop-debug')

    with loop_context(request.param, fast=fast) as _loop:
        if debug:
            _loop.set_debug(True)
        yield _loop


@pytest.fixture
def unused_port():
    """Return a port that is unused on the current host."""
    return _unused_port


@pytest.yield_fixture
def test_server(loop):
    """Factory to create a TestServer instance, given an app.

    test_server(app, **kwargs)
    """
    servers = []

    @asyncio.coroutine
    def go(app, **kwargs):
        server = TestServer(app)
        yield from server.start_server(loop=loop, **kwargs)
        servers.append(server)
        return server

    yield go

    @asyncio.coroutine
    def finalize():
        while servers:
            yield from servers.pop().close()

    loop.run_until_complete(finalize())


@pytest.yield_fixture
def raw_test_server(loop):
    """Factory to create a RawTestServer instance, given a web handler.

    raw_test_server(handler, **kwargs)
    """
    servers = []

    @asyncio.coroutine
    def go(handler, **kwargs):
        server = RawTestServer(handler)
        yield from server.start_server(loop=loop, **kwargs)
        servers.append(server)
        return server

    yield go

    @asyncio.coroutine
    def finalize():
        while servers:
            yield from servers.pop().close()

    loop.run_until_complete(finalize())


@pytest.yield_fixture
def test_client(loop):
    """Factory to create a TestClient instance.

    test_client(app, **kwargs)
    test_client(server, **kwargs)
    test_client(raw_server, **kwargs)
    """
    clients = []

    @asyncio.coroutine
    def go(__param, *args, **kwargs):
        if isinstance(__param, Application):
            assert not args, "args should be empty"
            client = TestClient(__param, loop=loop, **kwargs)
        elif isinstance(__param, TestServer):
            assert not args, "args should be empty"
            client = TestClient(__param, loop=loop, **kwargs)
        elif isinstance(__param, RawTestServer):
            assert not args, "args should be empty"
            client = TestClient(__param, loop=loop, **kwargs)
        else:
            __param = __param(loop, *args, **kwargs)
            client = TestClient(__param, loop=loop)

        yield from client.start_server()
        clients.append(client)
        return client

    yield go

    @asyncio.coroutine
    def finalize():
        while clients:
            yield from clients.pop().close()

    loop.run_until_complete(finalize())


@pytest.fixture
def shorttmpdir():
    """Provides a temporary directory with a shorter file system path than the
    tmpdir fixture.
    """
    tmpdir = path.local(tempfile.mkdtemp())
    yield tmpdir
    tmpdir.remove(rec=1)
