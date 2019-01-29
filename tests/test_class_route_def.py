import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher


@pytest.fixture
def router():
    return UrlDispatcher()


def test_head_class_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.head('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'HEAD'
    assert str(route.url_for()) == '/path'


def test_get_class_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.get('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 2

    route1 = list(router.routes())[0]
    assert route1.method == 'HEAD'
    assert str(route1.url_for()) == '/path'

    route2 = list(router.routes())[1]
    assert route2.method == 'GET'
    assert str(route2.url_for()) == '/path'


def test_post_class_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.post('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'POST'
    assert str(route.url_for()) == '/path'


def test_put_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.put('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'PUT'
    assert str(route.url_for()) == '/path'


def test_patch_class_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.patch('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'PATCH'
    assert str(route.url_for()) == '/path'


def test_delete_class_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.delete('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'DELETE'
    assert str(route.url_for()) == '/path'


def test_route_class_deco(router) -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.route('OTHER', '/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())
    router.add_routes(routes)

    assert len(router.routes()) == 1

    route = list(router.routes())[0]
    assert route.method == 'OTHER'
    assert str(route.url_for()) == '/path'


def test_class_route_def_sequence_protocol() -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.delete('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())

    assert len(routes) == 1

    info = routes[0]
    assert isinstance(info, web.RouteDef)
    assert info in routes
    assert list(routes)[0] is info


def test_repr_route_def() -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.get('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())

    rd = routes[0]
    assert repr(rd) == "<RouteDef GET /path -> 'handler'>"


def test_repr_route_def_with_extra_info() -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.get('/path', extra='info')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())

    rd = routes[0]
    assert repr(rd) == "<RouteDef GET /path -> 'handler', extra='info'>"


def test_repr_route_table_def() -> None:
    routes = web.ClassRouteTableDef()

    class RouteClass:
        @routes.get('/path')
        async def handler(self, request):
            pass

    routes.add_class(RouteClass())

    assert repr(routes) == "<ClassRouteTableDef count=1>"
