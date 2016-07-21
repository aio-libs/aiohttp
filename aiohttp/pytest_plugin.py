import asyncio
import contextlib

import pytest

from .test_utils import (TestClient, loop_context, setup_test_loop,
                         teardown_test_loop)
from .client_reqrep import ClientResponse


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


@pytest.yield_fixture
def test_client(loop):
    client = None

    @asyncio.coroutine
    def _create_from_app_factory(app_factory, *args, **kwargs):
        nonlocal client
        app = app_factory(loop, *args, **kwargs)
        client = TestClient(app)
        yield from client.start_server()
        return client

    yield _create_from_app_factory

    if client:
        client.close()


@pytest.fixture()
def build_aiohttp_client_response():
    """
    This is a parametrized fixture for building aiohttp client responses as
    needed.

    Example usage:
        ```
        resp = yield from build_aiohttp_client_response(
            "GET", "http://example.com",
            b"{'a': 'a', 'b': 'b'},
            {"CONTENT-TYPE": "application/json"},
            200)
        ```

        dict_resp = yield from resp.json()
    """
    @asyncio.coroutine
    def build_response(method, url, content, headers=None, status=200):
        cr = ClientResponse(method, url)
        cr._content = content
        cr.status = status
        cr.headers = headers or {}
        return cr
    return build_response
