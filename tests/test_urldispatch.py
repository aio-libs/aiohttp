import asyncio
import os
import pathlib
import re
from collections.abc import Container, Iterable, Mapping, MutableMapping, Sized
from urllib.parse import unquote

import pytest
from yarl import URL

import aiohttp
from aiohttp import hdrs, web
from aiohttp.test_utils import make_mocked_request
from aiohttp.web import HTTPMethodNotAllowed, HTTPNotFound, Response
from aiohttp.web_urldispatcher import (AbstractResource, ResourceRoute,
                                       SystemRoute, View,
                                       _defaultExpectHandler)


def make_request(method, path):
    return make_mocked_request(method, path)


def make_handler():

    @asyncio.coroutine
    def handler(request):
        return Response(request)  # pragma: no cover

    return handler


@pytest.fixture
def app(loop):
    return web.Application(loop=loop)


@pytest.fixture
def router(app):
    return app.router


@pytest.fixture
def fill_routes(router):
    def go():
        route1 = router.add_route('GET', '/plain', make_handler())
        route2 = router.add_route('GET', '/variable/{name}',
                                  make_handler())
        resource = router.add_static('/static',
                                     os.path.dirname(aiohttp.__file__))
        return [route1, route2] + list(resource)
    return go


def test_register_uncommon_http_methods(router):
    uncommon_http_methods = {
        'PROPFIND',
        'PROPPATCH',
        'COPY',
        'LOCK',
        'UNLOCK'
        'MOVE',
        'SUBSCRIBE',
        'UNSUBSCRIBE',
        'NOTIFY'
    }

    for method in uncommon_http_methods:
        router.add_route(method, '/handler/to/path', make_handler())


@asyncio.coroutine
def test_add_route_root(router):
    handler = make_handler()
    router.add_route('GET', '/', handler)
    req = make_request('GET', '/')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_simple(router):
    handler = make_handler()
    router.add_route('GET', '/handler/to/path', handler)
    req = make_request('GET', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_with_matchdict(router):
    handler = make_handler()
    router.add_route('GET', '/handler/{to}', handler)
    req = make_request('GET', '/handler/tail')
    info = yield from router.resolve(req)
    assert info is not None
    assert {'to': 'tail'} == info
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_with_add_get_shortcut(router):
    handler = make_handler()
    router.add_get('/handler/to/path', handler)
    req = make_request('GET', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_with_add_post_shortcut(router):
    handler = make_handler()
    router.add_post('/handler/to/path', handler)
    req = make_request('POST', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_with_add_put_shortcut(router):
    handler = make_handler()
    router.add_put('/handler/to/path', handler)
    req = make_request('PUT', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_with_add_patch_shortcut(router):
    handler = make_handler()
    router.add_patch('/handler/to/path', handler)
    req = make_request('PATCH', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_with_add_delete_shortcut(router):
    handler = make_handler()
    router.add_delete('/handler/to/path', handler)
    req = make_request('DELETE', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_route_with_add_head_shortcut(router):
    handler = make_handler()
    router.add_head('/handler/to/path', handler)
    req = make_request('HEAD', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert handler is info.handler
    assert info.route.name is None


@asyncio.coroutine
def test_add_with_name(router):
    handler = make_handler()
    router.add_route('GET', '/handler/to/path', handler,
                     name='name')
    req = make_request('GET', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 'name' == info.route.name


@asyncio.coroutine
def test_add_with_tailing_slash(router):
    handler = make_handler()
    router.add_route('GET', '/handler/to/path/', handler)
    req = make_request('GET', '/handler/to/path/')
    info = yield from router.resolve(req)
    assert info is not None
    assert {} == info
    assert handler is info.handler


def test_add_invalid_path(router):
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route('GET', '/{/', handler)


def test_add_url_invalid1(router):
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route('post', '/post/{id', handler)


def test_add_url_invalid2(router):
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route('post', '/post/{id{}}', handler)


def test_add_url_invalid3(router):
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route('post', '/post/{id{}', handler)


def test_add_url_invalid4(router):
    handler = make_handler()
    with pytest.raises(ValueError):
        router.add_route('post', '/post/{id"}', handler)


@asyncio.coroutine
def test_add_url_escaping(router):
    handler = make_handler()
    router.add_route('GET', '/+$', handler)

    req = make_request('GET', '/+$')
    info = yield from router.resolve(req)
    assert info is not None
    assert handler is info.handler


@asyncio.coroutine
def test_any_method(router):
    handler = make_handler()
    route = router.add_route(hdrs.METH_ANY, '/', handler)

    req = make_request('GET', '/')
    info1 = yield from router.resolve(req)
    assert info1 is not None
    assert route is info1.route

    req = make_request('POST', '/')
    info2 = yield from router.resolve(req)
    assert info2 is not None

    assert info1.route is info2.route


@asyncio.coroutine
def test_match_second_result_in_table(router):
    handler1 = make_handler()
    handler2 = make_handler()
    router.add_route('GET', '/h1', handler1)
    router.add_route('POST', '/h2', handler2)
    req = make_request('POST', '/h2')
    info = yield from router.resolve(req)
    assert info is not None
    assert {} == info
    assert handler2 is info.handler


@asyncio.coroutine
def test_raise_method_not_allowed(router):
    handler1 = make_handler()
    handler2 = make_handler()
    router.add_route('GET', '/', handler1)
    router.add_route('POST', '/', handler2)
    req = make_request('PUT', '/')

    match_info = yield from router.resolve(req)
    assert isinstance(match_info.route, SystemRoute)
    assert {} == match_info

    with pytest.raises(HTTPMethodNotAllowed) as ctx:
        yield from match_info.handler(req)

    exc = ctx.value
    assert 'PUT' == exc.method
    assert 405 == exc.status
    assert {'POST', 'GET'} == exc.allowed_methods


@asyncio.coroutine
def test_raise_method_not_found(router):
    handler = make_handler()
    router.add_route('GET', '/a', handler)
    req = make_request('GET', '/b')

    match_info = yield from router.resolve(req)
    assert isinstance(match_info.route, SystemRoute)
    assert {} == match_info

    with pytest.raises(HTTPNotFound) as ctx:
        yield from match_info.handler(req)

    exc = ctx.value
    assert 404 == exc.status


def test_double_add_url_with_the_same_name(router):
    handler1 = make_handler()
    handler2 = make_handler()
    router.add_route('GET', '/get', handler1, name='name')

    regexp = ("Duplicate 'name', already handled by")
    with pytest.raises(ValueError) as ctx:
        router.add_route('GET', '/get_other', handler2, name='name')
    assert re.match(regexp, str(ctx.value))


def test_route_plain(router):
    handler = make_handler()
    route = router.add_route('GET', '/get', handler, name='name')
    route2 = next(iter(router['name']))
    url = route2.url()
    assert '/get' == url
    assert route is route2


def test_route_unknown_route_name(router):
    with pytest.raises(KeyError):
        router['unknown']


def test_route_dynamic(router):
    handler = make_handler()
    route = router.add_route('GET', '/get/{name}', handler,
                             name='name')

    route2 = next(iter(router['name']))
    url = route2.url(parts={'name': 'John'})
    assert '/get/John' == url
    assert route is route2


def test_route_with_qs(router):
    handler = make_handler()
    router.add_route('GET', '/get', handler, name='name')

    url = router['name'].url(query=[('a', 'b'), ('c', '1')])
    assert '/get?a=b&c=1' == url


def test_add_static(router):
    resource = router.add_static('/st',
                                 os.path.dirname(aiohttp.__file__),
                                 name='static')
    assert router['static'] is resource
    url = resource.url(filename='/dir/a.txt')
    assert '/st/dir/a.txt' == url
    assert len(resource) == 2


def test_plain_not_match(router):
    handler = make_handler()
    router.add_route('GET', '/get/path', handler, name='name')
    route = router['name']
    assert route._match('/another/path') is None


def test_dynamic_not_match(router):
    handler = make_handler()
    router.add_route('GET', '/get/{name}', handler, name='name')
    route = router['name']
    assert route._match('/another/path') is None


@asyncio.coroutine
def test_static_not_match(router):
    router.add_static('/pre', os.path.dirname(aiohttp.__file__),
                      name='name')
    resource = router['name']
    ret = yield from resource.resolve(
        make_mocked_request('GET', '/another/path'))
    assert (None, set()) == ret


def test_dynamic_with_trailing_slash(router):
    handler = make_handler()
    router.add_route('GET', '/get/{name}/', handler, name='name')
    route = router['name']
    assert {'name': 'John'} == route._match('/get/John/')


def test_len(router):
    handler = make_handler()
    router.add_route('GET', '/get1', handler, name='name1')
    router.add_route('GET', '/get2', handler, name='name2')
    assert 2 == len(router)


def test_iter(router):
    handler = make_handler()
    router.add_route('GET', '/get1', handler, name='name1')
    router.add_route('GET', '/get2', handler, name='name2')
    assert {'name1', 'name2'} == set(iter(router))


def test_contains(router):
    handler = make_handler()
    router.add_route('GET', '/get1', handler, name='name1')
    router.add_route('GET', '/get2', handler, name='name2')
    assert 'name1' in router
    assert 'name3' not in router


def test_static_repr(router):
    router.add_static('/get', os.path.dirname(aiohttp.__file__),
                      name='name')
    assert re.match(r"<StaticResource 'name' /get", repr(router['name']))


def test_static_adds_slash(router):
    route = router.add_static('/prefix',
                              os.path.dirname(aiohttp.__file__))
    assert '/prefix' == route._prefix


def test_static_remove_trailing_slash(router):
    route = router.add_static('/prefix/',
                              os.path.dirname(aiohttp.__file__))
    assert '/prefix' == route._prefix


@asyncio.coroutine
def test_add_route_with_re(router):
    handler = make_handler()
    router.add_route('GET', r'/handler/{to:\d+}', handler)

    req = make_request('GET', '/handler/1234')
    info = yield from router.resolve(req)
    assert info is not None
    assert {'to': '1234'} == info

    router.add_route('GET', r'/handler/{name}.html', handler)
    req = make_request('GET', '/handler/test.html')
    info = yield from router.resolve(req)
    assert {'name': 'test'} == info


@asyncio.coroutine
def test_add_route_with_re_and_slashes(router):
    handler = make_handler()
    router.add_route('GET', r'/handler/{to:[^/]+/?}', handler)
    req = make_request('GET', '/handler/1234/')
    info = yield from router.resolve(req)
    assert info is not None
    assert {'to': '1234/'} == info

    router.add_route('GET', r'/handler/{to:.+}', handler)
    req = make_request('GET', '/handler/1234/5/6/7')
    info = yield from router.resolve(req)
    assert info is not None
    assert {'to': '1234/5/6/7'} == info


@asyncio.coroutine
def test_add_route_with_re_not_match(router):
    handler = make_handler()
    router.add_route('GET', r'/handler/{to:\d+}', handler)

    req = make_request('GET', '/handler/tail')
    match_info = yield from router.resolve(req)
    assert isinstance(match_info.route, SystemRoute)
    assert {} == match_info
    with pytest.raises(HTTPNotFound):
        yield from match_info.handler(req)


@asyncio.coroutine
def test_add_route_with_re_including_slashes(router):
    handler = make_handler()
    router.add_route('GET', r'/handler/{to:.+}/tail', handler)
    req = make_request('GET', '/handler/re/with/slashes/tail')
    info = yield from router.resolve(req)
    assert info is not None
    assert {'to': 're/with/slashes'} == info


def test_add_route_with_invalid_re(router):
    handler = make_handler()
    with pytest.raises(ValueError) as ctx:
        router.add_route('GET', r'/handler/{to:+++}', handler)
    s = str(ctx.value)
    assert s.startswith(
        "Bad pattern '\/handler\/(?P<to>+++)': nothing to repeat")
    assert ctx.value.__cause__ is None


def test_route_dynamic_with_regex_spec(router):
    handler = make_handler()
    route = router.add_route('GET', '/get/{num:^\d+}', handler,
                             name='name')

    url = route.url(parts={'num': '123'})
    assert '/get/123' == url


def test_route_dynamic_with_regex_spec_and_trailing_slash(router):
    handler = make_handler()
    route = router.add_route('GET', '/get/{num:^\d+}/', handler,
                             name='name')

    url = route.url(parts={'num': '123'})
    assert '/get/123/' == url


def test_route_dynamic_with_regex(router):
    handler = make_handler()
    route = router.add_route('GET', r'/{one}/{two:.+}', handler)

    url = route.url(parts={'one': 1, 'two': 2})
    assert '/1/2' == url


@asyncio.coroutine
def test_regular_match_info(router):
    handler = make_handler()
    router.add_route('GET', '/get/{name}', handler)

    req = make_request('GET', '/get/john')
    match_info = yield from router.resolve(req)
    assert {'name': 'john'} == match_info
    assert re.match("<MatchInfo {'name': 'john'}: .+<Dynamic.+>>",
                    repr(match_info))


@asyncio.coroutine
def test_not_found_repr(router):
    req = make_request('POST', '/path/to')
    match_info = yield from router.resolve(req)
    assert "<MatchInfoError 404: Not Found>" == repr(match_info)


@asyncio.coroutine
def test_not_allowed_repr(router):
    handler = make_handler()
    router.add_route('GET', '/path/to', handler)

    handler2 = make_handler()
    router.add_route('POST', '/path/to', handler2)

    req = make_request('PUT', '/path/to')
    match_info = yield from router.resolve(req)
    assert "<MatchInfoError 405: Method Not Allowed>" == repr(match_info)


def test_default_expect_handler(router):
    route = router.add_route('GET', '/', make_handler())
    assert route._expect_handler is _defaultExpectHandler


def test_custom_expect_handler_plain(router):

    @asyncio.coroutine
    def handler(request):
        pass

    route = router.add_route(
        'GET', '/', make_handler(), expect_handler=handler)
    assert route._expect_handler is handler
    assert isinstance(route, ResourceRoute)


def test_custom_expect_handler_dynamic(router):

    @asyncio.coroutine
    def handler(request):
        pass

    route = router.add_route(
        'GET', '/get/{name}', make_handler(), expect_handler=handler)
    assert route._expect_handler is handler
    assert isinstance(route, ResourceRoute)


def test_expect_handler_non_coroutine(router):

    def handler(request):
        pass

    with pytest.raises(AssertionError):
        router.add_route('GET', '/', make_handler(),
                         expect_handler=handler)


@asyncio.coroutine
def test_dynamic_match_non_ascii(router):
    handler = make_handler()
    router.add_route('GET', '/{var}', handler)
    req = make_request(
        'GET',
        '/%D1%80%D1%83%D1%81%20%D1%82%D0%B5%D0%BA%D1%81%D1%82')
    match_info = yield from router.resolve(req)
    assert {'var': 'рус текст'} == match_info


@asyncio.coroutine
def test_dynamic_match_with_static_part(router):
    handler = make_handler()
    router.add_route('GET', '/{name}.html', handler)
    req = make_request('GET', '/file.html')
    match_info = yield from router.resolve(req)
    assert {'name': 'file'} == match_info


@asyncio.coroutine
def test_dynamic_match_two_part2(router):
    handler = make_handler()
    router.add_route('GET', '/{name}.{ext}', handler)
    req = make_request('GET', '/file.html')
    match_info = yield from router.resolve(req)
    assert {'name': 'file', 'ext': 'html'} == match_info


@asyncio.coroutine
def test_dynamic_match_unquoted_path(router):
    handler = make_handler()
    router.add_route('GET', '/{path}/{subpath}', handler)
    resource_id = 'my%2Fpath%7Cwith%21some%25strange%24characters'
    req = make_request('GET', '/path/{0}'.format(resource_id))
    match_info = yield from router.resolve(req)
    assert match_info == {
        'path': 'path',
        'subpath': unquote(resource_id)
    }


def test_add_route_not_started_with_slash(router):
    with pytest.raises(ValueError):
        handler = make_handler()
        router.add_route('GET', 'invalid_path', handler)


def test_add_route_invalid_method(router):

    sample_bad_methods = {
        'BAD METHOD',
        'B@D_METHOD',
        '[BAD_METHOD]',
        '{BAD_METHOD}',
        '(BAD_METHOD)',
        'B?D_METHOD',
    }

    for bad_method in sample_bad_methods:
        with pytest.raises(ValueError):
            handler = make_handler()
            router.add_route(bad_method, '/path', handler)


def test_routes_view_len(router, fill_routes):
    fill_routes()
    assert 4 == len(router.routes())


def test_routes_view_iter(router, fill_routes):
    routes = fill_routes()
    assert list(routes) == list(router.routes())


def test_routes_view_contains(router, fill_routes):
    routes = fill_routes()
    for route in routes:
        assert route in router.routes()


def test_routes_abc(router):
    assert isinstance(router.routes(), Sized)
    assert isinstance(router.routes(), Iterable)
    assert isinstance(router.routes(), Container)


def test_named_resources_abc(router):
    assert isinstance(router.named_resources(), Mapping)
    assert not isinstance(router.named_resources(), MutableMapping)


def test_named_resources(router):
    route1 = router.add_route('GET', '/plain', make_handler(),
                              name='route1')
    route2 = router.add_route('GET', '/variable/{name}',
                              make_handler(), name='route2')
    route3 = router.add_static('/static',
                               os.path.dirname(aiohttp.__file__),
                               name='route3')
    names = {route1.name, route2.name, route3.name}

    assert 3 == len(router.named_resources())

    for name in names:
        assert name in router.named_resources()
        assert isinstance(router.named_resources()[name],
                          AbstractResource)


def test_resource_iter(router):
    resource = router.add_resource('/path')
    r1 = resource.add_route('GET', lambda req: None)
    r2 = resource.add_route('POST', lambda req: None)
    assert 2 == len(resource)
    assert [r1, r2] == list(resource)


def test_deprecate_bare_generators(router):
    resource = router.add_resource('/path')

    def gen(request):
        yield

    with pytest.warns(DeprecationWarning):
        resource.add_route('GET', gen)


def test_view_route(router):
    resource = router.add_resource('/path')

    route = resource.add_route('GET', View)
    assert View is route.handler


def test_resource_route_match(router):
    resource = router.add_resource('/path')
    route = resource.add_route('GET', lambda req: None)
    assert {} == route.resource._match('/path')


def test_error_on_double_route_adding(router):
    resource = router.add_resource('/path')

    resource.add_route('GET', lambda: None)
    with pytest.raises(RuntimeError):
        resource.add_route('GET', lambda: None)


def test_error_on_adding_route_after_wildcard(router):
    resource = router.add_resource('/path')

    resource.add_route('*', lambda: None)
    with pytest.raises(RuntimeError):
        resource.add_route('GET', lambda: None)


@asyncio.coroutine
def test_http_exception_is_none_when_resolved(router):
    handler = make_handler()
    router.add_route('GET', '/', handler)
    req = make_request('GET', '/')
    info = yield from router.resolve(req)
    assert info.http_exception is None


@asyncio.coroutine
def test_http_exception_is_not_none_when_not_resolved(router):
    handler = make_handler()
    router.add_route('GET', '/', handler)
    req = make_request('GET', '/abc')
    info = yield from router.resolve(req)
    assert info.http_exception.status == 404


@asyncio.coroutine
def test_match_info_get_info_plain(router):
    handler = make_handler()
    router.add_route('GET', '/', handler)
    req = make_request('GET', '/')
    info = yield from router.resolve(req)
    assert info.get_info() == {'path': '/'}


@asyncio.coroutine
def test_match_info_get_info_dynamic(router):
    handler = make_handler()
    router.add_route('GET', '/{a}', handler)
    req = make_request('GET', '/value')
    info = yield from router.resolve(req)
    assert info.get_info() == {
        'pattern': re.compile('\\/(?P<a>[^{}/]+)'),
        'formatter': '/{a}'}


@asyncio.coroutine
def test_match_info_get_info_dynamic2(router):
    handler = make_handler()
    router.add_route('GET', '/{a}/{b}', handler)
    req = make_request('GET', '/path/to')
    info = yield from router.resolve(req)
    assert info.get_info() == {
        'pattern': re.compile('\\/(?P<a>[^{}/]+)\\/(?P<b>[^{}/]+)'),
        'formatter': '/{a}/{b}'}


def test_static_resource_get_info(router):
    directory = pathlib.Path(aiohttp.__file__).parent
    resource = router.add_static('/st', directory)
    assert resource.get_info() == {'directory': directory,
                                   'prefix': '/st'}


@asyncio.coroutine
def test_system_route_get_info(router):
    handler = make_handler()
    router.add_route('GET', '/', handler)
    req = make_request('GET', '/abc')
    info = yield from router.resolve(req)
    assert info.get_info()['http_exception'].status == 404


def test_resources_view_len(router):
    router.add_resource('/plain')
    router.add_resource('/variable/{name}')
    assert 2 == len(router.resources())


def test_resources_view_iter(router):
    resource1 = router.add_resource('/plain')
    resource2 = router.add_resource('/variable/{name}')
    resources = [resource1, resource2]
    assert list(resources) == list(router.resources())


def test_resources_view_contains(router):
    resource1 = router.add_resource('/plain')
    resource2 = router.add_resource('/variable/{name}')
    resources = [resource1, resource2]
    for resource in resources:
        assert resource in router.resources()


def test_resources_abc(router):
    assert isinstance(router.resources(), Sized)
    assert isinstance(router.resources(), Iterable)
    assert isinstance(router.resources(), Container)


def test_static_route_user_home(router):
    here = pathlib.Path(aiohttp.__file__).parent
    home = pathlib.Path(os.path.expanduser('~'))
    if not str(here).startswith(str(home)):  # pragma: no cover
        pytest.skip("aiohttp folder is not placed in user's HOME")
    static_dir = '~/' + str(here.relative_to(home))
    route = router.add_static('/st', static_dir)
    assert here == route.get_info()['directory']


def test_static_route_points_to_file(router):
    here = pathlib.Path(aiohttp.__file__).parent / '__init__.py'
    with pytest.raises(ValueError):
        router.add_static('/st', here)


@asyncio.coroutine
def test_404_for_static_resource(router):
    resource = router.add_static('/st',
                                 os.path.dirname(aiohttp.__file__))
    ret = yield from resource.resolve(
        make_mocked_request('GET', '/unknown/path'))
    assert (None, set()) == ret


@asyncio.coroutine
def test_405_for_resource_adapter(router):
    resource = router.add_static('/st',
                                 os.path.dirname(aiohttp.__file__))
    ret = yield from resource.resolve(
        make_mocked_request('POST', '/st/abc.py'))
    assert (None, {'HEAD', 'GET'}) == ret


@asyncio.coroutine
def test_check_allowed_method_for_found_resource(router):
    handler = make_handler()
    resource = router.add_resource('/')
    resource.add_route('GET', handler)
    ret = yield from resource.resolve(make_mocked_request('GET', '/'))
    assert ret[0] is not None
    assert {'GET'} == ret[1]


def test_url_for_in_static_resource(router):
    resource = router.add_static('/static',
                                 os.path.dirname(aiohttp.__file__))
    assert URL('/static/file.txt') == resource.url_for(filename='file.txt')


def test_url_for_in_static_resource_pathlib(router):
    resource = router.add_static('/static',
                                 os.path.dirname(aiohttp.__file__))
    assert URL('/static/file.txt') == resource.url_for(
        filename=pathlib.Path('file.txt'))


def test_url_for_in_resource_route(router):
    route = router.add_route('GET', '/get/{name}', make_handler(),
                             name='name')
    assert URL('/get/John') == route.url_for(name='John')


def test_subapp_get_info(app, loop):
    subapp = web.Application(loop=loop)
    resource = subapp.add_subapp('/pre', subapp)
    assert resource.get_info() == {'prefix': '/pre', 'app': subapp}


def test_subapp_backward_compatible(router, loop):
    subapp = web.Application(loop=loop)
    resource = router.add_subapp('/pre', subapp)
    assert resource.get_info() == {'prefix': '/pre', 'app': subapp}


def test_subapp_url(app, loop):
    subapp = web.Application(loop=loop)
    resource = app.add_subapp('/pre', subapp)
    with pytest.raises(RuntimeError):
        resource.url()


def test_subapp_url_for(app, loop):
    subapp = web.Application(loop=loop)
    resource = app.add_subapp('/pre', subapp)
    with pytest.raises(RuntimeError):
        resource.url_for()


def test_subapp_repr(app, loop):
    subapp = web.Application(loop=loop)
    resource = app.add_subapp('/pre', subapp)
    assert repr(resource).startswith(
        '<PrefixedSubAppResource /pre -> <Application')


def test_subapp_len(app, loop):
    subapp = web.Application(loop=loop)
    subapp.router.add_get('/', make_handler())
    subapp.router.add_post('/', make_handler())
    resource = app.add_subapp('/pre', subapp)
    assert len(resource) == 2


def test_subapp_iter(app, loop):
    subapp = web.Application(loop=loop)
    r1 = subapp.router.add_get('/', make_handler())
    r2 = subapp.router.add_post('/', make_handler())
    resource = app.add_subapp('/pre', subapp)
    assert list(resource) == [r1, r2]


def test_invalid_route_name(router):
    with pytest.raises(ValueError):
        router.add_get('/', make_handler(), name='invalid name')


def test_frozen_router(router):
    router.freeze()
    with pytest.raises(RuntimeError):
        router.add_get('/', make_handler())


def test_frozen_router_subapp(app, loop):
    subapp = web.Application(loop=loop)
    subapp.freeze()
    with pytest.raises(RuntimeError):
        app.add_subapp('/', subapp)


def test_frozen_app_on_subapp(app, loop):
    app.freeze()
    subapp = web.Application(loop=loop)
    with pytest.raises(RuntimeError):
        app.add_subapp('/', subapp)


def test_set_options_route(router):
    resource = router.add_static('/static',
                                 os.path.dirname(aiohttp.__file__))
    options = None
    for route in resource:
        if route.method == 'OPTIONS':
            options = route
    assert options is None
    resource.set_options_route(make_handler())
    for route in resource:
        if route.method == 'OPTIONS':
            options = route
    assert options is not None

    with pytest.raises(RuntimeError):
        resource.set_options_route(make_handler())


def test_dynamic_url_with_name_started_from_undescore(router):
    route = router.add_route('GET', '/get/{_name}', make_handler())
    assert URL('/get/John') == route.url_for(_name='John')


def test_cannot_add_subapp_with_empty_prefix(app, loop):
    subapp = web.Application(loop=loop)
    with pytest.raises(ValueError):
        app.add_subapp('', subapp)


def test_cannot_add_subapp_with_slash_prefix(app, loop):
    subapp = web.Application(loop=loop)
    with pytest.raises(ValueError):
        app.add_subapp('/', subapp)


@asyncio.coroutine
def test_convert_empty_path_to_slash_on_freezing(router):
    handler = make_handler()
    route = router.add_get('', handler)
    resource = route.resource
    assert resource.get_info() == {'path': ''}
    router.freeze()
    assert resource.get_info() == {'path': '/'}
