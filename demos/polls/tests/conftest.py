import pathlib
import subprocess

import pytest

import aiohttp


@pytest.yield_fixture
def create_app(event_loop, unused_tcp_port):
    app = handler = srv = client_session = None

    async def create():
        nonlocal app, handler, srv, client_session
        import aiohttpdemo_polls.main
        app, host, port = await aiohttpdemo_polls.main.init(event_loop)
        handler = app.make_handler(debug=True, keep_alive_on=False)
        srv = await event_loop.create_server(handler, '127.0.0.1', port)
        url = "http://127.0.0.1:{}".format(port)
        client_session = aiohttp.ClientSession()
        return app, url, client_session

    yield create

    async def finish():
        await handler.finish_connections()
        await app.finish()
        await client_session.close()
        srv.close()
        await srv.wait_closed()

    event_loop.run_until_complete(finish())


BASE_DIR = pathlib.Path(__file__).parent.parent


@pytest.fixture
def app_db():
    subprocess.call(
        [(BASE_DIR / 'sql' / 'install.sh').as_posix()],
        shell=True,
        cwd=BASE_DIR.as_posix()
    )
