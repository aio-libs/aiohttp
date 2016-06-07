pytest_plugins = 'pytester'


def test_myplugin(testdir):
    testdir.makepyfile("""\
import asyncio
import pytest
from aiohttp import web

pytest_plugins = 'aiohttp.pytest_plugins'


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


@pytest.fixture
def client_alias(loop, test_client):
    cli = loop.run_until_complete(test_client(create_app))
    return cli


@asyncio.coroutine
def test_hello_with_alias(client_alias):
    resp = yield from client_alias.get('/')
    assert resp.status == 200
    text = yield from resp.text()
    assert 'Hello, world' in text
""")
    result = testdir.runpytest()
    result.assert_outcomes(passed=4, failed=1)
