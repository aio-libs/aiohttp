import asyncio


HELLO_WORLD = b"Hello world!\n"


@asyncio.coroutine
def application(environ, start_response):
    """Simplest possible application object"""
    status = '200 OK'
    response_headers = [('Content-type', 'text/plain')]
    start_response(status, response_headers)
    yield from asyncio.sleep(1)
    return [HELLO_WORLD]


@asyncio.coroutine
def close():
    print('Stopping Application')
    yield from asyncio.sleep(2)
    print('Application stopped')


setattr(application, 'close', close)


if __name__ == '__main__':
    print ("""This is an example of gunicorn worker that run application.
You must install gunicorn before running the example then.

Usage:

    gunicorn --worker-class aiohttp.worker.AsyncGunicornWorker gunicorn_worker

""")