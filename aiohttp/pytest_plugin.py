import asyncio
import contextlib

import pytest

from aiohttp.web import Application

from .test_utils import unused_port as _unused_port
from .test_utils import (TestClient, TestServer, loop_context, setup_test_loop,
                         teardown_test_loop)


@contextlib.contextmanager
def _passthrough_loop_context(loop):
    if loop:
        # loop already exists, pass it straight through
        yield loop
    else:
        # this shadows loop_context's standard behavior
        loop = setup_test_loop()
        yield loop
        teardown_test_loop(loop)


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
    if asyncio.iscoroutinefunction(pyfuncitem.function):
        existing_loop = pyfuncitem.funcargs.get('loop', None)
        with _passthrough_loop_context(existing_loop) as _loop:
            testargs = {arg: pyfuncitem.funcargs[arg]
                        for arg in pyfuncitem._fixtureinfo.argnames}

            task = _loop.create_task(pyfuncitem.obj(**testargs))
            _loop.run_until_complete(task)

        return True


@pytest.yield_fixture
def loop():
    with loop_context() as _loop:
        yield _loop


@pytest.fixture
def unused_port():
    return _unused_port


@pytest.yield_fixture
def test_server(loop):
    servers = []

    @asyncio.coroutine
    def go(app, **kwargs):
        assert app.loop is loop, \
            "Application is attached to other event loop"

        server = TestServer(app)
        yield from server.start_server(**kwargs)
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
    clients = []

    @asyncio.coroutine
    def go(__param, *args, **kwargs):
        if isinstance(__param, Application):
            assert not args, "args should be empty"
            assert not kwargs, "kwargs should be empty"
            assert __param.loop is loop, \
                "Application is attached to other event loop"
        elif isinstance(__param, TestServer):
            assert __param.app.loop is loop, \
                "TestServer is attached to other event loop"
        else:
            __param = __param(loop, *args, **kwargs)

        client = TestClient(__param)
        yield from client.start_server()
        clients.append(client)
        return client

    yield go

    @asyncio.coroutine
    def finalize():
        while clients:
            yield from clients.pop().close()

    loop.run_until_complete(finalize())
