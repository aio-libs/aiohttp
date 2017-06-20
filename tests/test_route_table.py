import asyncio

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher


@pytest.fixture
def router():
    return UrlDispatcher()


def test_get(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.get('/', handler)])
    assert len(router.routes()) == 2  # GET and HEAD

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'GET'

    route2 = list(router.routes())[1]
    assert route2.handler is handler
    assert route2.method == 'HEAD'


def test_head(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.head('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'HEAD'


def test_post(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.post('/', handler)])

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'POST'


def test_put(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.put('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'PUT'


def test_patch(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.patch('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'PATCH'


def test_delete(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.delete('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'DELETE'


def test_route(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.route('OPTIONS', '/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'OPTIONS'
