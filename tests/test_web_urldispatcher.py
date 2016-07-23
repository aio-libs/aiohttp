import pytest
import os
import shutil
import tempfile
import functools
import asyncio
import aiohttp.web
from aiohttp.test_utils import make_mocked_request

from aiohttp.web_urldispatcher import (SystemRoute, PlainRoute,
                                       UrlDispatcher)
from aiohttp.web import HTTPCreated, Response


@pytest.fixture(scope='function')
def tmp_dir_path(request):
    """
    Give a path for a temporary directory
    The directory is destroyed at the end of the test.
    """
    # Temporary directory.
    tmp_dir = tempfile.mkdtemp()

    def teardown():
        # Delete the whole directory:
        shutil.rmtree(tmp_dir)

    request.addfinalizer(teardown)
    return tmp_dir


@pytest.mark.parametrize("show_index,status", [(False, 403), (True, 200)])
@pytest.mark.run_loop
def test_access_root_of_static_handler(tmp_dir_path, create_app_and_client,
                                       show_index, status):
    """
    Tests the operation of static file server.
    Try to access the root of static file server, and make
    sure that correct HTTP statuses are returned depending if we directory
    index should be shown or not.
    """
    # Put a file inside tmp_dir_path:
    my_file_path = os.path.join(tmp_dir_path, 'my_file')
    with open(my_file_path, 'w') as fw:
        fw.write('hello')

    app, client = yield from create_app_and_client()

    # Register global static route:
    app.router.add_static('/', tmp_dir_path, show_index=show_index)

    # Request the root of the static directory.
    # Expect an 403 error page.
    r = yield from client.get('/')
    assert r.status == status
    # data = (yield from r.read())
    yield from r.release()


@pytest.mark.run_loop
def test_partialy_applied_handler(create_app_and_client):
    app, client = yield from create_app_and_client()

    @asyncio.coroutine
    def handler(data, request):
        return aiohttp.web.Response(body=data)

    app.router.add_route('GET', '/', functools.partial(handler, b'hello'))

    r = yield from client.get('/')
    data = (yield from r.read())
    assert data == b'hello'
    yield from r.release()


def test_system_route():
    route = SystemRoute(HTTPCreated(reason='test'))
    assert route.match('any') is None
    with pytest.raises(RuntimeError):
        route.url()
    assert "<SystemRoute 201: test>" == repr(route)
    assert 201 == route.status
    assert 'test' == route.reason


@pytest.mark.run_loop
def test_register_route():
    @asyncio.coroutine
    def handler(request):
        return Response()

    route = PlainRoute('GET', handler, 'test', '/handler/to/path')
    router = UrlDispatcher()
    router.register_route(route)

    req = make_mocked_request('GET', '/handler/to/path')
    info = yield from router.resolve(req)
    assert info is not None
    assert 0 == len(info)
    assert route is info.route
    assert handler is info.handler
    assert info.route.name == 'test'
