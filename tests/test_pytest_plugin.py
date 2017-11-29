import re
import sys

import pytest


pytest_plugins = 'pytester'

CONFTEST = '''
pytest_plugins = 'aiohttp.pytest_plugin'
'''


def test_aiohttp_plugin(testdir):
    testdir.makepyfile("""\
import asyncio
import pytest
from unittest import mock

from aiohttp import web

@asyncio.coroutine
def hello(request):
    return web.Response(body=b'Hello, world')


def create_app(loop):
    app = web.Application()
    app.router.add_route('GET', '/', hello)
    return app


@asyncio.coroutine
def test_hello(test_client):
    client = yield from test_client(create_app)
    resp = yield from client.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert 'Hello, world' in text


@asyncio.coroutine
def test_hello_from_app(test_client, loop):
    app = web.Application()
    app.router.add_get('/', hello)
    client = yield from test_client(app)
    resp = yield from client.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert 'Hello, world' in text


@asyncio.coroutine
def test_hello_with_loop(test_client, loop):
    client = yield from test_client(create_app)
    resp = yield from client.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert 'Hello, world' in text


@asyncio.coroutine
def test_hello_fails(test_client):
    client = yield from test_client(create_app)
    resp = yield from client.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert 'Hello, wield' in text


@asyncio.coroutine
def test_hello_with_fake_loop(test_client):
    with pytest.raises(RuntimeError):
        fake_loop = mock.Mock()
        yield from test_client(web.Application(loop=fake_loop))


@asyncio.coroutine
def test_set_args(test_client, loop):
    with pytest.raises(AssertionError):
        app = web.Application()
        yield from test_client(app, 1, 2, 3)


@asyncio.coroutine
def test_set_keyword_args(test_client, loop):
    app = web.Application()
    with pytest.raises(TypeError):
        yield from test_client(app, param=1)


@asyncio.coroutine
def test_noop():
    pass


@asyncio.coroutine
def previous(request):
    if request.method == 'POST':
        request.app['value'] = (yield from request.post())['value']
        return web.Response(body=b'thanks for the data')
    else:
        v = request.app.get('value', 'unknown')
        return web.Response(body='value: {}'.format(v).encode())


def create_stateful_app(loop):
    app = web.Application(loop=loop)
    app.router.add_route('*', '/', previous)
    return app


@pytest.fixture
def cli(loop, test_client):
    return loop.run_until_complete(test_client(create_stateful_app))


@asyncio.coroutine
def test_set_value(cli):
    resp = yield from cli.post('/', data={'value': 'foo'})
    assert resp.status == 200
    text = yield from resp.text()
    assert text == 'thanks for the data'
    assert cli.server.app['value'] == 'foo'


@asyncio.coroutine
def test_get_value(cli):
    resp = yield from cli.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert text == 'value: unknown'
    cli.server.app['value'] = 'bar'
    resp = yield from cli.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert text == 'value: bar'


def test_noncoro():
    assert True


@asyncio.coroutine
def test_client_failed_to_create(test_client):

    def make_app(loop):
        raise RuntimeError()

    with pytest.raises(RuntimeError):
        yield from test_client(make_app)

""")
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest('-p', 'no:sugar', '--loop=pyloop')
    result.assert_outcomes(passed=11, failed=1)


@pytest.mark.skipif(sys.version_info < (3, 5), reason='old python')
def test_warning_checks(testdir, capsys):
    testdir.makepyfile("""\
import asyncio

async def foobar():
    return 123

async def test_good():
    v = await foobar()
    assert v == 123

async def test_bad():
    foobar()
""")
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest('-p', 'no:sugar', '-s', '--loop=pyloop')
    result.assert_outcomes(passed=1, failed=1)
    stdout, _ = capsys.readouterr()
    assert ("test_warning_checks.py:__LINE__:coroutine 'foobar' was "
            "never awaited" in re.sub('\d{2,}', '__LINE__', stdout))


def test_aiohttp_plugin_async_fixture(testdir, capsys):
    testdir.makepyfile("""\
import asyncio
import pytest

from aiohttp import web


@asyncio.coroutine
def hello(request):
    return web.Response(body=b'Hello, world')


def create_app(loop):
    app = web.Application()
    app.router.add_route('GET', '/', hello)
    return app


@pytest.fixture
@asyncio.coroutine
def cli(test_client):
    client = yield from test_client(create_app)
    return client


@pytest.fixture
@asyncio.coroutine
def foo():
    return 42


@pytest.fixture
@asyncio.coroutine
def bar(request):
    # request should be accessible in async fixtures if needed
    return request.function


@asyncio.coroutine
def test_hello(cli):
    resp = yield from cli.get('/')
    assert resp.status == 200


def test_foo(loop, foo):
    assert foo == 42


def test_foo_without_loop(foo):
    # will raise an error because there is no loop
    pass


def test_bar(loop, bar):
    assert bar is test_bar
""")
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest('-p', 'no:sugar', '--loop=pyloop')
    result.assert_outcomes(passed=3, error=1)
    result.stdout.fnmatch_lines(
        "*Asynchronous fixtures must depend on the 'loop' fixture "
        "or be used in tests depending from it."
    )


@pytest.mark.skipif(sys.version_info < (3, 6), reason='old python')
def test_aiohttp_plugin_async_gen_fixture(testdir):
    testdir.makepyfile("""\
import asyncio
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
async def cli(test_client):
    yield await test_client(create_app)
    canary()


async def test_hello(cli):
    resp = await cli.get('/')
    assert resp.status == 200


def test_finalized():
    assert canary.called is True
""")
    testdir.makeconftest(CONFTEST)
    result = testdir.runpytest('-p', 'no:sugar', '--loop=pyloop')
    result.assert_outcomes(passed=2)
