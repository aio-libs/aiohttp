pytest_plugins = 'pytester'


def test_myplugin(testdir):
    testdir.makepyfile("""\
import asyncio
import pytest
from aiohttp import web

pytest_plugins = 'aiohttp.pytest_plugin'


@asyncio.coroutine
def hello(request):
    return web.Response(body=b'Hello, world')


def create_app(loop):
    app = web.Application(loop=loop)
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
    assert cli.app['value'] == 'foo'


@asyncio.coroutine
def test_get_value(cli):
    resp = yield from cli.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert text == 'value: unknown'
    cli.app['value'] = 'bar'
    resp = yield from cli.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert text == 'value: bar'
""")
    result = testdir.runpytest('-p', 'no:sugar')
    result.assert_outcomes(passed=5, failed=1)
