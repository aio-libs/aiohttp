.. aiohttp documentation master file, created by
   sphinx-quickstart on Wed Mar  5 12:35:35 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

aiohttp
=======

HTTP client/server for :term:`asyncio` (:pep:`3156`).

.. _GitHub: https://github.com/KeepSafe/aiohttp
.. _Freenode: http://freenode.net


Features
--------

- Supports both :ref:`aiohttp-client` and :ref:`HTTP Server <aiohttp-web>`.
- Supports both :ref:`Server WebSockets <aiohttp-web-websockets>` and
  :ref:`Client WebSockets <aiohttp-client-websockets>` out-of-the-box.
- Web-server has :ref:`aiohttp-web-middlewares` and pluggable routing.

Library Installation
--------------------

::

   pip install aiohttp

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
    except KeyboardInterrupt:
        pass


Source code
-----------

The project is hosted on GitHub_

Please feel free to file an issue on the `bug tracker
<https://github.com/KeepSafe/aiohttp/issues>`_ if you have found a bug
or have some suggestion in order to improve the library.

The library uses `Travis <https://travis-ci.org/KeepSafe/aiohttp>`_ for
Continuous Integration.

IRC channel
-----------

You can discuss the library on Freenode_ at **#aio-libs** channel.


Dependencies
------------

- Python 3.3 and :term:`asyncio` or Python 3.4+
- *chardet* library

Contributing
------------

Please read the :ref:`instructions for contributors<aiohttp-contributing>`
before making a Pull Request.


Authors and License
-------------------

The ``aiohttp`` package is written mainly by Nikolay Kim and Andrew Svetlov.

It's *Apache 2* licensed and freely available.

Feel free to improve this package and send a pull request to GitHub_.

Contents:

.. toctree::
   :maxdepth: 2

   client
   client_reference
   client_websockets
   web
   web_reference
   server
   multidict
   multipart
   api
   gunicorn
   contributing
   changes
   glossary

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
