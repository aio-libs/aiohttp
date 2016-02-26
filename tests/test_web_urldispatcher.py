import pytest
import tempfile
import aiohttp
from aiohttp import web
import os
import shutil
import asyncio

# Timeout in seconds for an asynchronous test:
ASYNC_TEST_TIMEOUT = 1

class ExceptAsyncTestTimeout(Exception): pass

def run_timeout(cor,loop,timeout=ASYNC_TEST_TIMEOUT):
    """
    Run a given coroutine with timeout.
    """
    task_with_timeout = asyncio.wait_for(cor,timeout,loop=loop)
    try:
        return loop.run_until_complete(task_with_timeout)
    except asyncio.futures.TimeoutError:
        # Timeout:
        raise ExceptAsyncTestTimeout()


@pytest.fixture(scope='function')
def tloop(request):
    """
    Obtain a test loop. We want each test case to have its own loop.
    """
    # Create a new test loop:
    tloop = asyncio.new_event_loop()
    asyncio.set_event_loop(None)

    def teardown():
        # Close the test loop:
        tloop.close()

    request.addfinalizer(teardown)
    return tloop


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


def test_access_root_of_static_handler(tloop, tmp_dir_path, unused_port):
    """
    Tests the operation of static file server.
    Try to access the root of static file server, and make
    sure that a proper not found error is returned.
    """
    SERVER_PORT = unused_port()
    SERVER_HOST = 'localhost'

    # Put a file inside tmp_dir_path:
    my_file_path = os.path.join(tmp_dir_path,'my_file')
    with open(my_file_path,'w') as fw:
        fw.write('hello')

    asyncio.set_event_loop(None)
    app = web.Application(loop=tloop)
    # Register global static route:
    app.router.add_static('/', tmp_dir_path)

    @asyncio.coroutine
    def inner_cor():
        handler = app.make_handler()
        srv = yield from tloop.create_server(handler,\
                SERVER_HOST,SERVER_PORT ,reuse_address=True) 

        # Request the root of the static directory.
        # Expect an 404 error page.
        url = 'http://{}:{}/'.format(\
                SERVER_HOST,SERVER_PORT) 

        r = ( yield from aiohttp.get(url,loop=tloop) )
        assert r.status == 404
        # data = (yield from r.read())
        yield from r.release()

        srv.close()
        yield from srv.wait_closed()

        yield from app.shutdown()
        yield from handler.finish_connections(10.0)
        yield from app.cleanup()


    run_timeout(inner_cor(),tloop,timeout=5)
