import asyncio
import functools
import os
import shutil
import tempfile
from unittest import mock
from unittest.mock import MagicMock

import pytest

from aiohttp import web
from aiohttp.web_urldispatcher import SystemRoute


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


@pytest.mark.parametrize("show_index,status,data",
                         [(False, 403, None),
                          (True, 200,
                           b'<html>\n<head>\n<title>Index of /</title>\n'
                           b'</head>\n<body>\n<h1>Index of /</h1>\n<ul>\n'
                           b'<li><a href="/my_dir">my_dir/</a></li>\n'
                           b'<li><a href="/my_file">my_file</a></li>\n'
                           b'</ul>\n</body>\n</html>')])
@asyncio.coroutine
def test_access_root_of_static_handler(tmp_dir_path, loop, test_client,
                                       show_index, status, data):
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

    my_dir_path = os.path.join(tmp_dir_path, 'my_dir')
    os.mkdir(my_dir_path)

    my_file_path = os.path.join(my_dir_path, 'my_file_in_dir')
    with open(my_file_path, 'w') as fw:
        fw.write('world')

    app = web.Application(loop=loop)

    # Register global static route:
    app.router.add_static('/', tmp_dir_path, show_index=show_index)
    client = yield from test_client(app)

    # Request the root of the static directory.
    r = yield from client.get('/')
    assert r.status == status

    if data:
        assert r.headers['Content-Type'] == "text/html; charset=utf-8"
        read_ = (yield from r.read())
        assert read_ == data
    yield from r.release()


@pytest.mark.parametrize('data', ['hello world'])
@asyncio.coroutine
def test_follow_symlink(tmp_dir_path, loop, test_client, data):
    """
    Tests the access to a symlink, in static folder
    """
    my_dir_path = os.path.join(tmp_dir_path, 'my_dir')
    os.mkdir(my_dir_path)

    my_file_path = os.path.join(my_dir_path, 'my_file_in_dir')
    with open(my_file_path, 'w') as fw:
        fw.write(data)

    my_symlink_path = os.path.join(tmp_dir_path, 'my_symlink')
    os.symlink(my_dir_path, my_symlink_path)

    app = web.Application(loop=loop)

    # Register global static route:
    app.router.add_static('/', tmp_dir_path, follow_symlinks=True)
    client = yield from test_client(app)

    # Request the root of the static directory.
    r = yield from client.get('/my_symlink/my_file_in_dir')
    assert r.status == 200
    assert (yield from r.text()) == data

    yield from r.release()


@pytest.mark.parametrize('dir_name,filename,data', [
    ('', 'test file.txt', 'test text'),
    ('test dir name', 'test dir file .txt', 'test text file folder')
])
@asyncio.coroutine
def test_access_to_the_file_with_spaces(tmp_dir_path, loop, test_client,
                                        dir_name, filename, data):
    """
    Checks operation of static files with spaces
    """

    my_dir_path = os.path.join(tmp_dir_path, dir_name)

    if dir_name:
        os.mkdir(my_dir_path)

    my_file_path = os.path.join(my_dir_path, filename)

    with open(my_file_path, 'w') as fw:
        fw.write(data)

    app = web.Application(loop=loop)

    url = os.path.join('/', dir_name, filename)

    app.router.add_static('/', tmp_dir_path)
    client = yield from test_client(app)

    r = yield from client.get(url)
    assert r.status == 200
    assert (yield from r.text()) == data
    yield from r.release()


@asyncio.coroutine
def test_access_non_existing_resource(tmp_dir_path, loop, test_client):
    """
    Tests accessing non-existing resource
    Try to access a non-exiting resource and make sure that 404 HTTP status
    returned.
    """
    app = web.Application(loop=loop)

    # Register global static route:
    app.router.add_static('/', tmp_dir_path, show_index=True)
    client = yield from test_client(app)

    # Request the root of the static directory.
    r = yield from client.get('/non_existing_resource')
    assert r.status == 404
    yield from r.release()


@asyncio.coroutine
def test_unauthorized_folder_access(tmp_dir_path, loop, test_client):
    """
    Tests the unauthorized access to a folder of static file server.
    Try to list a folder content of static file server when server does not
    have permissions to do so for the folder.
    """
    my_dir_path = os.path.join(tmp_dir_path, 'my_dir')
    os.mkdir(my_dir_path)

    app = web.Application(loop=loop)

    with mock.patch('pathlib.Path.__new__') as path_constructor:
        path = MagicMock()
        path.joinpath.return_value = path
        path.resolve.return_value = path
        path.iterdir.return_value.__iter__.side_effect = PermissionError()
        path_constructor.return_value = path

        # Register global static route:
        app.router.add_static('/', tmp_dir_path, show_index=True)
        client = yield from test_client(app)

        # Request the root of the static directory.
        r = yield from client.get('/my_dir')
        assert r.status == 403

    yield from r.release()


@asyncio.coroutine
def test_access_symlink_loop(tmp_dir_path, loop, test_client):
    """
    Tests the access to a looped symlink, which could not be resolved.
    """
    my_dir_path = os.path.join(tmp_dir_path, 'my_symlink')
    os.symlink(my_dir_path, my_dir_path)

    app = web.Application(loop=loop)

    # Register global static route:
    app.router.add_static('/', tmp_dir_path, show_index=True)
    client = yield from test_client(app)

    # Request the root of the static directory.
    r = yield from client.get('/my_symlink')
    assert r.status == 404

    yield from r.release()


@asyncio.coroutine
def test_access_special_resource(tmp_dir_path, loop, test_client):
    """
    Tests the access to a resource that is neither a file nor a directory.
    Checks that if a special resource is accessed (f.e. named pipe or UNIX
    domain socket) then 404 HTTP status returned.
    """
    app = web.Application(loop=loop)

    with mock.patch('pathlib.Path.__new__') as path_constructor:
        special = MagicMock()
        special.is_dir.return_value = False
        special.is_file.return_value = False

        path = MagicMock()
        path.joinpath.side_effect = lambda p: (special if p == 'special'
                                               else path)
        path.resolve.return_value = path
        special.resolve.return_value = special

        path_constructor.return_value = path

        # Register global static route:
        app.router.add_static('/', tmp_dir_path, show_index=True)
        client = yield from test_client(app)

        # Request the root of the static directory.
        r = yield from client.get('/special')
        assert r.status == 404

    yield from r.release()


@asyncio.coroutine
def test_partialy_applied_handler(loop, test_client):
    app = web.Application(loop=loop)

    @asyncio.coroutine
    def handler(data, request):
        return web.Response(body=data)

    app.router.add_route('GET', '/', functools.partial(handler, b'hello'))
    client = yield from test_client(app)

    r = yield from client.get('/')
    data = (yield from r.read())
    assert data == b'hello'
    yield from r.release()


def test_system_route():
    route = SystemRoute(web.HTTPCreated(reason='test'))
    with pytest.raises(RuntimeError):
        route.url()
    with pytest.raises(RuntimeError):
        route.url_for()
    assert route.name is None
    assert route.resource is None
    assert "<SystemRoute 201: test>" == repr(route)
    assert 201 == route.status
    assert 'test' == route.reason
