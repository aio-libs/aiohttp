"""
Example for running Application using the `aiohttp.web` CLI.

Run this app using::

    $ python -m aiohttp.web web_app.init
"""

from aiohttp.web import Application, Response


def hello_world(req):
    return Response(text="Hello World")


def init(args):
    app = Application()
    app.router.add_route('GET', '/', hello_world)

    return app
