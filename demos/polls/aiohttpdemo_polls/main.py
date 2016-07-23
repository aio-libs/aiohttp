import asyncio
import logging
import pathlib

import aiohttp_jinja2
import jinja2
from aiohttp import web

from aiohttpdemo_polls.middlewares import setup_middlewares
from aiohttpdemo_polls.routes import setup_routes
from aiohttpdemo_polls.utils import load_config
from aiohttpdemo_polls.db import init_postgres

PROJ_ROOT = pathlib.Path(__file__).parent


async def close_pg(app):
    app['db'].close()
    await app['db'].wait_closed()


async def init(loop):
    # setup application and extensions
    app = web.Application(loop=loop)
    aiohttp_jinja2.setup(
        app, loader=jinja2.PackageLoader('aiohttpdemo_polls', 'templates'))
    # load config from yaml file in current dir
    conf = load_config(str(pathlib.Path('.') / 'config' / 'polls.yaml'))

    # create connection to the database
    db = await init_postgres(conf['postgres'], loop)
    app['db'] = db

    app.on_cleanup.append(close_pg)
    # setup views and routes
    setup_routes(app, PROJ_ROOT)
    setup_middlewares(app)

    host, port = conf['host'], conf['port']
    return app, host, port


def main():
    # init logging
    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()
    app, host, port = loop.run_until_complete(init(loop))
    web.run_app(app, host=host, port=port)


if __name__ == '__main__':
    main()
