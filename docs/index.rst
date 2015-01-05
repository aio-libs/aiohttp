.. aiohttp documentation master file, created by
   sphinx-quickstart on Wed Mar  5 12:35:35 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

aiohttp
=======

http client/server for asyncio (:pep:`3156`).

.. _GitHub: https://github.com/KeepSafe/aiohttp


Features
--------

- Supports both :ref:`aiohttp-client` and :ref:`aiohttp-web`.
- Supports WebSockets out-of-the-box.
- Web-server has middlewares and pluggable routing.

Library Installation
--------------------

::

   pip3 install aiohttp

For smart detection of *Content-Type* by client API you would like to
install *chardet* also::

   pip install chardet


Source code
-----------

The project is hosted on GitHub_

Please feel free to file an issue on `bug tracker
<https://github.com/KeepSafe/aiohttp/issues>`_ if you have found a bug
or have some suggestion for library improvement.

The library uses `Travis <https://travis-ci.org/KeepSafe/aiohttp>`_ for
Continious Integration.


Dependencies
------------

- Python 3.3 and *asyncio* or Python 3.4+
- optional *chardet* library

Contributing
------------

Please read :ref:`aiohttp-contributing` before making Pull Request.


Authors and License
-------------------

The ``aiohttp`` package is written mainly by Nikolay Kim and Andrew Svetlov.
It's *Apache 2* licensed and freely available.
Feel free to improve this package and send a pull request to GitHub_.

Getting Started
---------------

Client example::

    import asyncio
    import aiohttp

    @asyncio.coroutine
    def fetch_page(url):
        response = yield from aiohttp.request('GET', url)
        assert response.status == 200
        return (yield from response.read())

    content = asyncio.get_event_loop().run_until_complete(
        fetch_page('http://python.org'))
    print(content)

Server example::

    import asyncio
    from aiohttp import web


    @asyncio.coroutine
    def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(body=text.encode('utf-8'))


    @asyncio.coroutine
    def init(loop):
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/{name}', handle)

        srv = yield from loop.create_server(app.make_handler(),
                                            '127.0.0.1', 8080)
        print("Server started at http://127.0.0.1:8080")
        return srv

    loop = asyncio.get_event_loop()
    loop.run_until_complete(init(loop))
    try:
        loop.run_forever()
    except KeyboardInterrrupt:
        pass

Contents:

.. toctree::
   :maxdepth: 2

   client
   web
   server
   api

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
