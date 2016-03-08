import pytest
import os
import shutil
import tempfile
import functools
import asyncio
import aiohttp.web


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


@pytest.mark.run_loop
def test_access_root_of_static_handler(tmp_dir_path, create_app_and_client):
    """
    Tests the operation of static file server.
    Try to access the root of static file server, and make
    sure that a proper not found error is returned.
    """
    # Put a file inside tmp_dir_path:
    my_file_path = os.path.join(tmp_dir_path, 'my_file')
    with open(my_file_path, 'w') as fw:
        fw.write('hello')

    app, client = yield from create_app_and_client()

    # Register global static route:
    app.router.add_static('/', tmp_dir_path)

    # Request the root of the static directory.
    # Expect an 404 error page.
    r = yield from client.get('/')
    assert r.status == 404
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
