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
- Web-server has :ref:`aiohttp-web-middlewares`,
  :ref:`aiohttp-web-signals` and pluggable routing.

Library Installation
--------------------

::

   $ pip install aiohttp

You may want to install *optional* :term:`cchardet` library as faster
replacement for :term:`chardet`::

   $ pip install cchardet

Getting Started
---------------

Client example::

    import asyncio
    import aiohttp

    async def fetch_page(client, url):
        async with client.get(url) as response:
            assert response.status == 200
            return await response.read()

    loop = asyncio.get_event_loop()
    client = aiohttp.ClientSession(loop=loop)
    content = loop.run_until_complete(
        fetch_page(client, 'http://python.org'))
    print(content)
    client.close()

Server example::

    import asyncio
    from aiohttp import web

    async def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(body=text.encode('utf-8'))

    async def init(loop):
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/{name}', handle)

        srv = await loop.create_server(app.make_handler(),
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


Dependencies
------------

- Python Python 3.4.1+
- *chardet* library
- *Optional* :term:`cchardet` library as faster replacement for
  :term:`chardet`.

  Install it explicitly via::

     $ pip install cchardet


Discussion list
---------------

*aio-libs* google group: https://groups.google.com/forum/#!forum/aio-libs

Feel free to post your questions and ideas here.

Contributing
------------

Please read the :ref:`instructions for contributors<aiohttp-contributing>`
before making a Pull Request.


Authors and License
-------------------

The ``aiohttp`` package is written mostly by Nikolay Kim and Andrew Svetlov.

It's *Apache 2* licensed and freely available.

Feel free to improve this package and send a pull request to GitHub_.

Contents
--------

.. toctree::

   client
   client_reference
   client_websockets
   web
   web_reference
   server
   multidict
   multipart
   api
   logging
   gunicorn
   contributing
   changes
   Python 3.3 support <python33>
   glossary

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. disqus::
