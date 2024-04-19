import os
import platform

pytest_plugins = "pytester"

CONFTEST = """
pytest_plugins = 'aiohttp.pytest_plugin'
"""


IS_PYPY = platform.python_implementation() == "PyPy"


def test_aiohttp_plugin(testdir) -> None:
    testdir.makepyfile(
        """\
import pytest
from unittest import mock

from aiohttp import web

value = web.AppKey('value', str)


async def hello(request):
    return web.Response(body=b'Hello, world')


def create_app(loop=None):
    app = web.Application()
    app.router.add_route('GET', '/', hello)
    return app


async def test_hello(aiohttp_client) -> None:
    client = await aiohttp_client(create_app)
    resp = await client.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert 'Hello, world' in text


async def test_hello_from_app(aiohttp_client, loop) -> None:
    app = web.Application()
    app.router.add_get('/', hello)
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert 'Hello, world' in text


async def test_hello_with_loop(aiohttp_client, loop) -> None:
    client = await aiohttp_client(create_app)
    resp = await client.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert 'Hello, world' in text


async def test_set_args(aiohttp_client, loop) -> None:
    with pytest.raises(AssertionError):
        app = web.Application()
        await aiohttp_client(app, 1, 2, 3)


async def test_set_keyword_args(aiohttp_client, loop) -> None:
    app = web.Application()
    with pytest.raises(TypeError):
        await aiohttp_client(app, param=1)


async def test_noop() -> None:
    pass


async def previous(request):
    if request.method == 'POST':
        with pytest.deprecated_call():  # FIXME: this isn't actually called
            request.app[value] = (await request.post())['value']
        return web.Response(body=b'thanks for the data')
    else:
        v = request.app.get(value, 'unknown')
        return web.Response(body='value: {}'.format(v).encode())


def create_stateful_app(loop):
    app = web.Application()
    app.router.add_route('*', '/', previous)
    return app


@pytest.fixture
def cli(loop, aiohttp_client):
    return loop.run_until_complete(aiohttp_client(create_stateful_app))


async def test_set_value(cli) -> None:
    resp = await cli.post('/', data={'value': 'foo'})
    assert resp.status == 200
    text = await resp.text()
    assert text == 'thanks for the data'
    assert cli.server.app[value] == 'foo'


async def test_get_value(cli) -> None:
    resp = await cli.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert text == 'value: unknown'
    with pytest.warns(DeprecationWarning):
        cli.server.app[value] = 'bar'
    resp = await cli.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert text == 'value: bar'


def test_noncoro() -> None:
    assert True


async def test_failed_to_create_client(aiohttp_client) -> None:
    def make_app(loop):
        raise RuntimeError()

    with pytest.raises(RuntimeError):
        await aiohttp_client(make_app)


async def test_custom_port_aiohttp_client(aiohttp_client, aiohttp_unused_port):
    port = aiohttp_unused_port()
    client = await aiohttp_client(create_app, server_kwargs={'port': port})
    assert client.port == port
    resp = await client.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert 'Hello, world' in text


async def test_custom_port_test_server(aiohttp_server, aiohttp_unused_port):
    app = create_app()
    port = aiohttp_unused_port()
    server = await aiohttp_server(app, port=port)
    assert server.port == port
"""
    )
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest("-p", "no:sugar", "--aiohttp-loop=pyloop")
    result.assert_outcomes(passed=12)


def test_warning_checks(testdir) -> None:
    testdir.makepyfile(
        """\

async def foobar():
    return 123

async def test_good() -> None:
    v = await foobar()
    assert v == 123

async def test_bad() -> None:
    foobar()
"""
    )
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest(
        "-p", "no:sugar", "-s", "-W", "default", "--aiohttp-loop=pyloop"
    )
    expected_outcomes = (
        {"failed": 0, "passed": 2}
        if IS_PYPY and bool(os.environ.get("PYTHONASYNCIODEBUG"))
        else {"failed": 1, "passed": 1}
    )
    # Under PyPy "coroutine 'foobar' was never awaited" does not happen.
    result.assert_outcomes(**expected_outcomes)


def test_aiohttp_plugin_async_fixture(testdir, capsys) -> None:
    testdir.makepyfile(
        """\
import pytest

from aiohttp import web


async def hello(request):
    return web.Response(body=b'Hello, world')


def create_app():
    app = web.Application()
    app.router.add_route('GET', '/', hello)
    return app


@pytest.fixture
async def cli(aiohttp_client, loop):
    client = await aiohttp_client(create_app())
    return client


@pytest.fixture
async def foo():
    return 42


@pytest.fixture
async def bar(request):
    # request should be accessible in async fixtures if needed
    return request.function


async def test_hello(cli, loop) -> None:
    resp = await cli.get('/')
    assert resp.status == 200


def test_foo(loop, foo) -> None:
    assert foo == 42


def test_foo_without_loop(foo) -> None:
    # will raise an error because there is no loop
    pass


def test_bar(loop, bar) -> None:
    assert bar is test_bar
"""
    )
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest("-p", "no:sugar", "--aiohttp-loop=pyloop")
    result.assert_outcomes(passed=3, errors=1)
    result.stdout.fnmatch_lines(
        "*Asynchronous fixtures must depend on the 'loop' fixture "
        "or be used in tests depending from it."
    )


def test_aiohttp_plugin_async_gen_fixture(testdir) -> None:
    testdir.makepyfile(
        """\
import pytest
from unittest import mock

from aiohttp import web


canary = mock.Mock()


async def hello(request):
    return web.Response(body=b'Hello, world')


def create_app(loop):
    app = web.Application()
    app.router.add_route('GET', '/', hello)
    return app


@pytest.fixture
async def cli(aiohttp_client):
    yield await aiohttp_client(create_app)
    canary()


async def test_hello(cli) -> None:
    resp = await cli.get('/')
    assert resp.status == 200


def test_finalized() -> None:
    assert canary.called is True
"""
    )
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest("-p", "no:sugar", "--aiohttp-loop=pyloop")
    result.assert_outcomes(passed=2)
