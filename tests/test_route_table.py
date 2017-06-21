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

    route = list(router.routes())[1]
    assert route.handler is handler
    assert route.method == 'GET'
    assert str(route.url_for()) == '/'

    route2 = list(router.routes())[0]
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
    assert str(route.url_for()) == '/'


def test_post(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.post('/', handler)])

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'POST'
    assert str(route.url_for()) == '/'


def test_put(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.put('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'PUT'
    assert str(route.url_for()) == '/'


def test_patch(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.patch('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'PATCH'
    assert str(route.url_for()) == '/'


def test_delete(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.delete('/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'DELETE'
    assert str(route.url_for()) == '/'


def test_route(router):
    @asyncio.coroutine
    def handler(request):
        pass

    router.add_routes([web.route('OTHER', '/', handler)])
    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.handler is handler
    assert route.method == 'OTHER'
    assert str(route.url_for()) == '/'
