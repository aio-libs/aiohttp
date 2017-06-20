.. aiohttp documentation master file, created by
   sphinx-quickstart on Wed Mar  5 12:35:35 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

aiohttp: Asynchronous HTTP Client/Server
========================================

HTTP client/server for :term:`asyncio` (:pep:`3156`).

.. _GitHub: https://github.com/aio-libs/aiohttp
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

.. code-block:: bash

   $ pip install aiohttp

You may want to install *optional* :term:`cchardet` library as faster
replacement for :term:`chardet`:

.. code-block:: bash

   $ pip install cchardet

For speeding up DNS resolving by client API you may install
:term:`aiodns` as well.
This option is highly recommended:

.. code-block:: bash

   $ pip install aiodns

Getting Started
---------------

Client example::

    import aiohttp
    import asyncio
    import async_timeout

    async def fetch(session, url):
        with async_timeout.timeout(10):
            async with session.get(url) as response:
                return await response.text()

    async def main():
        async with aiohttp.ClientSession() as session:
            html = await fetch(session, 'http://python.org')
            print(html)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

Server example::

    from aiohttp import web

    async def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(text=text)

    app = web.Application()
    app.router.add_get('/', handle)
    app.router.add_get('/{name}', handle)

    web.run_app(app)

.. note::

   Throughout this documentation, examples utilize the `async/await` syntax
   introduced by :pep:`492` that is only valid for Python 3.5+.

   If you are using Python 3.4, please replace ``await`` with
   ``yield from`` and ``async def`` with a ``@coroutine`` decorator.
   For example, this::

       async def coro(...):
           ret = await f()

   should be replaced by::

       @asyncio.coroutine
       def coro(...):
           ret = yield from f()


Tutorial
--------

:ref:`Polls tutorial <aiohttp-tutorial>`


Source code
-----------

The project is hosted on GitHub_

Please feel free to file an issue on the `bug tracker
<https://github.com/aio-libs/aiohttp/issues>`_ if you have found a bug
or have some suggestion in order to improve the library.

The library uses `Travis <https://travis-ci.org/aio-libs/aiohttp>`_ for
Continuous Integration.


Dependencies
------------

- Python 3.4.2+
- *chardet*
- *multidict*
- *async_timeout*
- *yarl*
- *Optional* :term:`cchardet` as faster replacement for
  :term:`chardet`.

  Install it explicitly via:

  .. code-block:: bash

     $ pip install cchardet

- *Optional* :term:`aiodns` for fast DNS resolving. The
  library is highly recommended.

  .. code-block:: bash

     $ pip install aiodns


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


.. _aiohttp-backward-compatibility-policy:

Policy for Backward Incompatible Changes
----------------------------------------

*aiohttp* keeps backward compatibility.

After deprecating some *Public API* (method, class, function argument,
etc.) the library guaranties the usage of *deprecated API* is still
allowed at least for a year and half after publishing new release with
deprecation.

All deprecations are reflected in documentation and raises
:exc:`DeprecationWarning`.

Sometimes we are forced to break the own rule for sake of very strong
reason.  Most likely the reason is a critical bug which cannot be
solved without major API change, but we are working hard for keeping
these changes as rare as possible.


Contents
--------

.. toctree::

   migration
   client
   client_reference
   tutorial
   web
   web_reference
   web_lowlevel
   abc
   multipart
   streams
   api
   logging
   testing
   deployment
   faq
   third_party
   essays
   contributing
   changes
   glossary

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. disqus::
  :title: aiohttp documentation
