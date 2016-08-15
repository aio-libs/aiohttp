import asyncio
import os
import pathlib
import re
import unittest
from collections.abc import Container, Iterable, Mapping, MutableMapping, Sized
from urllib.parse import unquote

import aiohttp.web
from aiohttp import hdrs
from aiohttp.test_utils import make_mocked_request
from aiohttp.web import (HTTPMethodNotAllowed, HTTPNotFound, Response,
                         UrlDispatcher)
from aiohttp.web_urldispatcher import (AbstractResource, DynamicRoute,
                                       PlainRoute, ResourceRoute, SystemRoute,
                                       View, _defaultExpectHandler)


class TestUrlDispatcher(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.router = UrlDispatcher()

    def tearDown(self):
        self.loop.close()

    def make_request(self, method, path):
        return make_mocked_request(method, path)

    def make_handler(self):

        @asyncio.coroutine
        def handler(request):
            return Response(request)  # pragma: no cover

        return handler

    def test_register_route_checks(self):
        self.assertRaises(
            AssertionError, self.router.register_route, object())

        handler = self.make_handler()
        route = PlainRoute('GET', handler, 'test', '/handler/to/path')
        self.router.register_route(route)
        self.assertRaises(ValueError, self.router.register_route, route)

        route = PlainRoute('GET', handler, '1bad name', '/handler/to/path')
        self.assertRaises(ValueError, self.router.register_route, route)

        route = PlainRoute('GET', handler, 'return', '/handler/to/path')
        self.assertRaises(ValueError, self.router.register_route, route)

        route = PlainRoute('GET', handler, 'test.test:test-test',
                           '/handler/to/path')
        self.router.register_route(route)

    def test_register_uncommon_http_methods(self):
        handler = self.make_handler()

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
            PlainRoute(method, handler, 'url', '/handler/to/path')

    def test_add_route_root(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_simple(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/to/path', handler)
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_with_matchdict(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/{to}', handler)
        req = self.make_request('GET', '/handler/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 'tail'}, info)
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_with_add_get_shortcut(self):
        handler = self.make_handler()
        self.router.add_get('/handler/to/path', handler)
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_with_add_post_shortcut(self):
        handler = self.make_handler()
        self.router.add_post('/handler/to/path', handler)
        req = self.make_request('POST', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_with_add_put_shortcut(self):
        handler = self.make_handler()
        self.router.add_put('/handler/to/path', handler)
        req = self.make_request('PUT', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_with_add_patch_shortcut(self):
        handler = self.make_handler()
        self.router.add_patch('/handler/to/path', handler)
        req = self.make_request('PATCH', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_route_with_add_delete_shortcut(self):
        handler = self.make_handler()
        self.router.add_delete('/handler/to/path', handler)
        req = self.make_request('DELETE', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual(0, len(info))
        self.assertIs(handler, info.handler)
        self.assertIsNone(info.route.name)

    def test_add_with_name(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/to/path', handler,
                              name='name')
        req = self.make_request('GET', '/handler/to/path')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual('name', info.route.name)

    def test_add_with_tailing_slash(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/handler/to/path/', handler)
        req = self.make_request('GET', '/handler/to/path/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info)
        self.assertIs(handler, info.handler)

    def test_add_invalid_path(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('GET', '/{/', handler)

    def test_add_url_invalid1(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id', handler)

    def test_add_url_invalid2(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id{}}', handler)

    def test_add_url_invalid3(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id{}', handler)

    def test_add_url_invalid4(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError):
            self.router.add_route('post', '/post/{id"}', handler)

    def test_add_url_escaping(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/+$', handler)

        req = self.make_request('GET', '/+$')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertIs(handler, info.handler)

    def test_any_method(self):
        handler = self.make_handler()
        route = self.router.add_route(hdrs.METH_ANY, '/', handler)

        req = self.make_request('GET', '/')
        info1 = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info1)
        self.assertIs(route, info1.route)

        req = self.make_request('POST', '/')
        info2 = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info2)

        self.assertIs(info1.route, info2.route)

    def test_match_second_result_in_table(self):
        handler1 = self.make_handler()
        handler2 = self.make_handler()
        self.router.add_route('GET', '/h1', handler1)
        self.router.add_route('POST', '/h2', handler2)
        req = self.make_request('POST', '/h2')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({}, info)
        self.assertIs(handler2, info.handler)

    def test_raise_method_not_allowed(self):
        handler1 = self.make_handler()
        handler2 = self.make_handler()
        self.router.add_route('GET', '/', handler1)
        self.router.add_route('POST', '/', handler2)
        req = self.make_request('PUT', '/')

        match_info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsInstance(match_info.route, SystemRoute)
        self.assertEqual({}, match_info)

        with self.assertRaises(HTTPMethodNotAllowed) as ctx:
            self.loop.run_until_complete(match_info.handler(req))

        exc = ctx.exception
        self.assertEqual('PUT', exc.method)
        self.assertEqual(405, exc.status)
        self.assertEqual({'POST', 'GET'}, exc.allowed_methods)

    def test_raise_method_not_found(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/a', handler)
        req = self.make_request('GET', '/b')

        match_info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsInstance(match_info.route, SystemRoute)
        self.assertEqual({}, match_info)

        with self.assertRaises(HTTPNotFound) as ctx:
            self.loop.run_until_complete(match_info.handler(req))

        exc = ctx.exception
        self.assertEqual(404, exc.status)

    def test_double_add_url_with_the_same_name(self):
        handler1 = self.make_handler()
        handler2 = self.make_handler()
        self.router.add_route('GET', '/get', handler1, name='name')

        regexp = ("Duplicate 'name', already handled by")
        with self.assertRaisesRegex(ValueError, regexp):
            self.router.add_route('GET', '/get_other', handler2, name='name')

    def test_route_plain(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get', handler, name='name')
        route2 = next(iter(self.router['name']))
        url = route2.url()
        self.assertEqual('/get', url)
        self.assertIs(route, route2)

    def test_route_unknown_route_name(self):
        with self.assertRaises(KeyError):
            self.router['unknown']

    def test_route_dynamic(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get/{name}', handler,
                                      name='name')

        route2 = next(iter(self.router['name']))
        url = route2.url(parts={'name': 'John'})
        self.assertEqual('/get/John', url)
        self.assertIs(route, route2)

    def test_route_with_qs(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get', handler, name='name')

        url = self.router['name'].url(query=[('a', 'b'), ('c', 1)])
        self.assertEqual('/get?a=b&c=1', url)

    def test_add_static(self):
        route = self.router.add_static('/st',
                                       os.path.dirname(aiohttp.__file__),
                                       name='static')
        resource = self.router['static']
        url = resource.url(filename='/dir/a.txt')
        self.assertEqual('/st/dir/a.txt', url)
        self.assertIs(route, next(iter(resource)))

    def test_plain_not_match(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/path', handler, name='name')
        route = self.router['name']
        self.assertIsNone(route._match('/another/path'))

    def test_dynamic_not_match(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/{name}', handler, name='name')
        route = self.router['name']
        self.assertIsNone(route._match('/another/path'))

    def test_static_not_match(self):
        self.router.add_static('/pre', os.path.dirname(aiohttp.__file__),
                               name='name')
        route = self.router['name']
        self.assertIsNone(route._route.match('/another/path'))

    def test_dynamic_with_trailing_slash(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get/{name}/', handler, name='name')
        route = self.router['name']
        self.assertEqual({'name': 'John'}, route._match('/get/John/'))

    def test_len(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get1', handler, name='name1')
        self.router.add_route('GET', '/get2', handler, name='name2')
        self.assertEqual(2, len(self.router))

    def test_iter(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get1', handler, name='name1')
        self.router.add_route('GET', '/get2', handler, name='name2')
        self.assertEqual({'name1', 'name2'}, set(iter(self.router)))

    def test_contains(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/get1', handler, name='name1')
        self.router.add_route('GET', '/get2', handler, name='name2')
        self.assertIn('name1', self.router)
        self.assertNotIn('name3', self.router)

    def test_plain_repr(self):
        handler = self.make_handler()
        route = PlainRoute('GET', handler, 'name', '/get/path')
        self.assertRegex(repr(route),
                         r"<PlainRoute 'name' \[GET\] /get/path")

    def test_dynamic_repr(self):
        handler = self.make_handler()
        route = DynamicRoute('GET', handler, 'name',
                             'pattern', '/get/{path}')
        self.assertRegex(repr(route),
                         r"<DynamicRoute 'name' \[GET\] /get/{path}")

    def test_static_repr(self):
        self.router.add_static('/get', os.path.dirname(aiohttp.__file__),
                               name='name')
        self.assertRegex(repr(next(iter(self.router['name']))),
                         r"<StaticRoute 'name' \[GET\] /get/")

    def test_static_adds_slash(self):
        route = self.router.add_static('/prefix',
                                       os.path.dirname(aiohttp.__file__))
        self.assertEqual('/prefix/', route._prefix)

    def test_static_dont_add_trailing_slash(self):
        route = self.router.add_static('/prefix/',
                                       os.path.dirname(aiohttp.__file__))
        self.assertEqual('/prefix/', route._prefix)

    def test_add_route_with_re(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:\d+}', handler)

        req = self.make_request('GET', '/handler/1234')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': '1234'}, info)

        self.router.add_route('GET', r'/handler/{name}.html', handler)
        req = self.make_request('GET', '/handler/test.html')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertEqual({'name': 'test'}, info)

    def test_add_route_with_re_and_slashes(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:[^/]+/?}', handler)
        req = self.make_request('GET', '/handler/1234/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': '1234/'}, info)

        self.router.add_route('GET', r'/handler/{to:.+}', handler)
        req = self.make_request('GET', '/handler/1234/5/6/7')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': '1234/5/6/7'}, info)

    def test_add_route_with_re_not_match(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:\d+}', handler)

        req = self.make_request('GET', '/handler/tail')
        match_info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsInstance(match_info.route, SystemRoute)
        self.assertEqual({}, match_info)
        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(match_info.handler(req))

    def test_add_route_with_re_including_slashes(self):
        handler = self.make_handler()
        self.router.add_route('GET', r'/handler/{to:.+}/tail', handler)
        req = self.make_request('GET', '/handler/re/with/slashes/tail')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNotNone(info)
        self.assertEqual({'to': 're/with/slashes'}, info)

    def test_add_route_with_invalid_re(self):
        handler = self.make_handler()
        with self.assertRaises(ValueError) as ctx:
            self.router.add_route('GET', r'/handler/{to:+++}', handler)
        s = str(ctx.exception)
        self.assertTrue(s.startswith(
            "Bad pattern '\/handler\/(?P<to>+++)': nothing to repeat"), s)
        self.assertIsNone(ctx.exception.__cause__)

    def test_route_dynamic_with_regex_spec(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get/{num:^\d+}', handler,
                                      name='name')

        url = route.url(parts={'num': '123'})
        self.assertEqual('/get/123', url)

    def test_route_dynamic_with_regex_spec_and_trailing_slash(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', '/get/{num:^\d+}/', handler,
                                      name='name')

        url = route.url(parts={'num': '123'})
        self.assertEqual('/get/123/', url)

    def test_route_dynamic_with_regex(self):
        handler = self.make_handler()
        route = self.router.add_route('GET', r'/{one}/{two:.+}', handler)

        url = route.url(parts={'one': 1, 'two': 2})
        self.assertEqual('/1/2', url)

    def test_regular_match_info(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/get/{name}', handler)

            req = self.make_request('GET', '/get/john')
            match_info = yield from self.router.resolve(req)
            self.assertEqual({'name': 'john'}, match_info)
            self.maxDiff = None
            self.assertRegex(repr(match_info),
                             "<MatchInfo {'name': 'john'}: .+<Dynamic.+>>")

        self.loop.run_until_complete(go())

    def test_not_found_repr(self):

        @asyncio.coroutine
        def go():
            req = self.make_request('POST', '/path/to')
            match_info = yield from self.router.resolve(req)
            self.assertEqual("<MatchInfoError 404: Not Found>",
                             repr(match_info))

        self.loop.run_until_complete(go())

    def test_not_allowed_repr(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/path/to', handler)

            handler2 = self.make_handler()
            self.router.add_route('POST', '/path/to', handler2)

            req = self.make_request('PUT', '/path/to')
            match_info = yield from self.router.resolve(req)
            self.assertEqual("<MatchInfoError 405: Method Not Allowed>",
                             repr(match_info))

        self.loop.run_until_complete(go())

    def test_default_expect_handler(self):
        route = self.router.add_route('GET', '/', self.make_handler())
        self.assertIs(route._expect_handler, _defaultExpectHandler)

    def test_custom_expect_handler_plain(self):

        @asyncio.coroutine
        def handler(request):
            pass

        route = self.router.add_route(
            'GET', '/', self.make_handler(), expect_handler=handler)
        self.assertIs(route._expect_handler, handler)
        self.assertIsInstance(route, ResourceRoute)

    def test_custom_expect_handler_dynamic(self):

        @asyncio.coroutine
        def handler(request):
            pass

        route = self.router.add_route(
            'GET', '/get/{name}', self.make_handler(), expect_handler=handler)
        self.assertIs(route._expect_handler, handler)
        self.assertIsInstance(route, ResourceRoute)

    def test_expect_handler_non_coroutine(self):

        def handler(request):
            pass

        self.assertRaises(
            AssertionError, self.router.add_route,
            'GET', '/', self.make_handler(), expect_handler=handler)

    def test_dynamic_match_non_ascii(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/{var}', handler)
            req = self.make_request(
                'GET',
                '/%D1%80%D1%83%D1%81%20%D1%82%D0%B5%D0%BA%D1%81%D1%82')
            match_info = yield from self.router.resolve(req)
            self.assertEqual({'var': 'рус текст'}, match_info)

        self.loop.run_until_complete(go())

    def test_dynamic_match_with_static_part(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/{name}.html', handler)
            req = self.make_request('GET', '/file.html')
            match_info = yield from self.router.resolve(req)
            self.assertEqual({'name': 'file'}, match_info)

        self.loop.run_until_complete(go())

    def test_dynamic_match_two_part2(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/{name}.{ext}', handler)
            req = self.make_request('GET', '/file.html')
            match_info = yield from self.router.resolve(req)
            self.assertEqual({'name': 'file', 'ext': 'html'}, match_info)

        self.loop.run_until_complete(go())

    def test_dynamic_match_unquoted_path(self):

        @asyncio.coroutine
        def go():
            handler = self.make_handler()
            self.router.add_route('GET', '/{path}/{subpath}', handler)
            resource_id = 'my%2Fpath%7Cwith%21some%25strange%24characters'
            req = self.make_request('GET', '/path/{0}'.format(resource_id))
            match_info = yield from self.router.resolve(req)
            self.assertEqual(match_info, {
                'path': 'path',
                'subpath': unquote(resource_id)
            })

        self.loop.run_until_complete(go())

    def test_add_route_not_started_with_slash(self):
        with self.assertRaises(ValueError):
            handler = self.make_handler()
            self.router.add_route('GET', 'invalid_path', handler)

    def test_add_route_invalid_method(self):

        sample_bad_methods = {
            'BAD METHOD',
            'B@D_METHOD',
            '[BAD_METHOD]',
            '{BAD_METHOD}',
            '(BAD_METHOD)',
            'B?D_METHOD',
        }

        for bad_method in sample_bad_methods:
            with self.assertRaises(ValueError):
                handler = self.make_handler()
                self.router.add_route(bad_method, '/path', handler)

    def fill_routes(self):
        route1 = self.router.add_route('GET', '/plain', self.make_handler())
        route2 = self.router.add_route('GET', '/variable/{name}',
                                       self.make_handler())
        route3 = self.router.add_static('/static',
                                        os.path.dirname(aiohttp.__file__))
        return route1, route2, route3

    def test_routes_view_len(self):
        self.fill_routes()
        self.assertEqual(3, len(self.router.routes()))

    def test_routes_view_iter(self):
        routes = self.fill_routes()
        self.assertEqual(list(routes), list(self.router.routes()))

    def test_routes_view_contains(self):
        routes = self.fill_routes()
        for route in routes:
            self.assertIn(route, self.router.routes())

    def test_routes_abc(self):
        self.assertIsInstance(self.router.routes(), Sized)
        self.assertIsInstance(self.router.routes(), Iterable)
        self.assertIsInstance(self.router.routes(), Container)

    def fill_named_resources(self):
        route1 = self.router.add_route('GET', '/plain', self.make_handler(),
                                       name='route1')
        route2 = self.router.add_route('GET', '/variable/{name}',
                                       self.make_handler(), name='route2')
        route3 = self.router.add_static('/static',
                                        os.path.dirname(aiohttp.__file__),
                                        name='route3')
        return route1.name, route2.name, route3.name

    def test_named_routes_abc(self):
        self.assertIsInstance(self.router.named_routes(), Mapping)
        self.assertNotIsInstance(self.router.named_routes(), MutableMapping)

    def test_named_resources_abc(self):
        self.assertIsInstance(self.router.named_resources(), Mapping)
        self.assertNotIsInstance(self.router.named_resources(), MutableMapping)

    def test_named_routes(self):
        self.fill_named_resources()

        with self.assertWarns(DeprecationWarning):
            self.assertEqual(3, len(self.router.named_routes()))

    def test_named_resources(self):
        names = self.fill_named_resources()

        self.assertEqual(3, len(self.router.named_resources()))

        for name in names:
            self.assertIn(name, self.router.named_routes())
            self.assertIsInstance(self.router.named_routes()[name],
                                  AbstractResource)

    def test_resource_adapter_not_match(self):
        route = PlainRoute('GET', lambda req: None, None, '/path')
        self.router.register_route(route)
        resource = route.resource
        self.assertIsNotNone(resource)
        self.assertIsNone(resource._route.match('/another/path'))

    def test_resource_adapter_resolve_not_math(self):
        route = PlainRoute('GET', lambda req: None, None, '/path')
        self.router.register_route(route)
        resource = route.resource
        self.assertEqual((None, set()),
                         self.loop.run_until_complete(
                             resource.resolve('GET', '/another/path')))

    def test_resource_adapter_resolve_bad_method(self):
        route = PlainRoute('POST', lambda req: None, None, '/path')
        self.router.register_route(route)
        resource = route.resource
        self.assertEqual((None, {'POST'}),
                         self.loop.run_until_complete(
                         resource.resolve('GET', '/path')))

    def test_resource_adapter_resolve_wildcard(self):
        route = PlainRoute('*', lambda req: None, None, '/path')
        self.router.register_route(route)
        resource = route.resource
        match_info, allowed = self.loop.run_until_complete(
            resource.resolve('GET', '/path'))
        self.assertEqual(allowed, {'*'})  # TODO: expand wildcard
        self.assertIsNotNone(match_info)

    def test_resource_adapter_iter(self):
        route = PlainRoute('GET', lambda req: None, None, '/path')
        self.router.register_route(route)
        resource = route.resource
        self.assertEqual(1, len(resource))
        self.assertEqual([route], list(resource))

    def test_resource_iter(self):
        resource = self.router.add_resource('/path')
        r1 = resource.add_route('GET', lambda req: None)
        r2 = resource.add_route('POST', lambda req: None)
        self.assertEqual(2, len(resource))
        self.assertEqual([r1, r2], list(resource))

    def test_deprecate_bare_generators(self):
        resource = self.router.add_resource('/path')

        def gen(request):
            yield

        with self.assertWarns(DeprecationWarning):
            resource.add_route('GET', gen)

    def test_view_route(self):
        resource = self.router.add_resource('/path')

        route = resource.add_route('GET', View)
        self.assertIs(View, route.handler)

    def test_resource_route_match(self):
        resource = self.router.add_resource('/path')
        route = resource.add_route('GET', lambda req: None)
        self.assertEqual({}, route.resource._match('/path'))

    def test_plain_route_url(self):
        route = PlainRoute('GET', lambda req: None, None, '/path')
        self.router.register_route(route)
        self.assertEqual('/path?arg=1', route.url(query={'arg': 1}))

    def test_dynamic_route_url(self):
        route = DynamicRoute('GET', lambda req: None, None,
                             '<pattern>', '/{path}')
        self.router.register_route(route)
        self.assertEqual('/path?arg=1', route.url(parts={'path': 'path'},
                                                  query={'arg': 1}))

    def test_dynamic_route_match_not_found(self):
        route = DynamicRoute('GET', lambda req: None, None,
                             re.compile('/path/(?P<to>.+)'), '/path/{to}')
        self.router.register_route(route)
        self.assertEqual(None, route.match('/another/path'))

    def test_dynamic_route_match_found(self):
        route = DynamicRoute('GET', lambda req: None, None,
                             re.compile('/path/(?P<to>.+)'), '/path/{to}')
        self.router.register_route(route)
        self.assertEqual({'to': 'to'}, route.match('/path/to'))

    def test_deprecate_register_route(self):
        route = PlainRoute('GET', lambda req: None, None, '/path')
        with self.assertWarns(DeprecationWarning):
            self.router.register_route(route)

    def test_error_on_double_route_adding(self):
        resource = self.router.add_resource('/path')

        resource.add_route('GET', lambda: None)
        with self.assertRaises(RuntimeError):
            resource.add_route('GET', lambda: None)

    def test_error_on_adding_route_after_wildcard(self):
        resource = self.router.add_resource('/path')

        resource.add_route('*', lambda: None)
        with self.assertRaises(RuntimeError):
            resource.add_route('GET', lambda: None)

    def test_http_exception_is_none_when_resolved(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertIsNone(info.http_exception)

    def test_http_exception_is_not_none_when_not_resolved(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/abc')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertEqual(info.http_exception.status, 404)

    def test_match_info_get_info_plain(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertEqual(info.get_info(), {'path': '/'})

    def test_match_info_get_info_dynamic(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/{a}', handler)
        req = self.make_request('GET', '/value')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertEqual(info.get_info(),
                         {'pattern': re.compile('^\\/(?P<a>[^{}/]+)$'),
                          'formatter': '/{a}'})

    def test_resource_adapter_get_info(self):
        directory = pathlib.Path(aiohttp.__file__).parent
        route = self.router.add_static('/st', directory)
        self.assertEqual(route.resource.get_info(), {'directory': directory,
                                                     'prefix': '/st/'})

    def test_plain_old_style_route_get_info(self):
        handler = self.make_handler()
        route = PlainRoute('GET', handler, 'test', '/handler/to/path')
        self.router.register_route(route)
        self.assertEqual(route.get_info(), {'path': '/handler/to/path'})

    def test_dynamic_old_style_get_info(self):
        handler = self.make_handler()
        route = DynamicRoute('GET', handler, 'name',
                             '<pattern>', '/get/{path}')
        self.router.register_route(route)
        self.assertEqual(route.get_info(), {'formatter': '/get/{path}',
                                            'pattern': '<pattern>'})

    def test_system_route_get_info(self):
        handler = self.make_handler()
        self.router.add_route('GET', '/', handler)
        req = self.make_request('GET', '/abc')
        info = self.loop.run_until_complete(self.router.resolve(req))
        self.assertEqual(info.get_info()['http_exception'].status, 404)

    def fill_resources(self):
        resource1 = self.router.add_resource('/plain')
        resource2 = self.router.add_resource('/variable/{name}')
        return resource1, resource2

    def test_resources_view_len(self):
        self.fill_resources()
        self.assertEqual(2, len(self.router.resources()))

    def test_resources_view_iter(self):
        resources = self.fill_resources()
        self.assertEqual(list(resources), list(self.router.resources()))

    def test_resources_view_contains(self):
        resources = self.fill_resources()
        for resource in resources:
            self.assertIn(resource, self.router.resources())

    def test_resources_abc(self):
        self.assertIsInstance(self.router.resources(), Sized)
        self.assertIsInstance(self.router.resources(), Iterable)
        self.assertIsInstance(self.router.resources(), Container)

    def test_static_route_user_home(self):
        here = pathlib.Path(aiohttp.__file__).parent
        home = pathlib.Path(os.path.expanduser('~'))
        if not str(here).startswith(str(home)):  # pragma: no cover
            self.skipTest("aiohttp folder is not placed in user's HOME")
        static_dir = '~/' + str(here.relative_to(home))
        route = self.router.add_static('/st', static_dir)
        self.assertEqual(here, route.get_info()['directory'])

    def test_static_route_points_to_file(self):
        here = pathlib.Path(aiohttp.__file__).parent / '__init__.py'
        with self.assertRaises(ValueError):
            self.router.add_static('/st', here)

    def test_404_for_resource_adapter(self):
        route = self.router.add_static('/st',
                                       os.path.dirname(aiohttp.__file__))
        resource = route.resource
        ret = self.loop.run_until_complete(
            resource.resolve('GET', '/unknown/path'))
        self.assertEqual((None, set()), ret)

    def test_405_for_resource_adapter(self):
        route = self.router.add_static('/st',
                                       os.path.dirname(aiohttp.__file__))
        resource = route.resource
        ret = self.loop.run_until_complete(
            resource.resolve('POST', '/st/abc.py'))
        self.assertEqual((None, {'GET'}), ret)

    def test_check_allowed_method_for_found_resource(self):
        handler = self.make_handler()
        resource = self.router.add_resource('/')
        resource.add_route('GET', handler)
        ret = self.loop.run_until_complete(resource.resolve('GET', '/'))
        self.assertIsNotNone(ret[0])
        self.assertEqual({'GET'}, ret[1])
