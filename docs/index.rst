.. aiohttp documentation master file, created by
   sphinx-quickstart on Wed Mar  5 12:35:35 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==================
Welcome to AIOHTTP
==================

Asynchronous HTTP Client/Server for :term:`asyncio` and Python.

Current version is |release|.

.. _GitHub: https://github.com/aio-libs/aiohttp


Key Features
============

- Supports both :ref:`aiohttp-client` and :ref:`HTTP Server <aiohttp-web>`.
- Supports both :ref:`Server WebSockets <aiohttp-web-websockets>` and
  :ref:`Client WebSockets <aiohttp-client-websockets>` out-of-the-box
  without the Callback Hell.
- Web-server has :ref:`aiohttp-web-middlewares`,
  :ref:`aiohttp-web-signals` and plugable routing.

.. _aiohttp-installation:

Library Installation
====================

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

Installing speedups altogether
------------------------------

The following will get you ``aiohttp`` along with :term:`chardet`,
:term:`aiodns` and ``brotlipy`` in one bundle. No need to type
separate commands anymore!

.. code-block:: bash

   $ pip install aiohttp[speedups]

Getting Started
===============

Client example
--------------

.. code-block:: python

  import aiohttp
  import asyncio

  async def main():

      async with aiohttp.ClientSession() as session:
          async with session.get('http://python.org') as response:

              print("Status:", response.status)
              print("Content-type:", response.headers['content-type'])

              html = await response.text()
              print("Body:", html[:15], "...")

  loop = asyncio.get_event_loop()
  loop.run_until_complete(main())

This prints:

.. code-block:: text

    Status: 200
    Content-type: text/html; charset=utf-8
    Body: <!doctype html> ...

Coming from :term:`requests` ? Read :ref:`why we need so many lines <aiohttp-request-lifecycle>`.

Server example:
----------------

.. code-block:: python

    from aiohttp import web

    async def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(text=text)

    app = web.Application()
    app.add_routes([web.get('/', handle),
                    web.get('/{name}', handle)])

    if __name__ == '__main__':
        web.run_app(app)


For more information please visit :ref:`aiohttp-client` and
:ref:`aiohttp-web` pages.

What's new in aiohttp 3?
========================

Go to :ref:`aiohttp_whats_new_3_0` page for aiohttp 3.0 major release
changes.


Tutorial
========

:ref:`Polls tutorial <aiohttp-demos-polls-beginning>`


Source code
===========

The project is hosted on GitHub_

Please feel free to file an issue on the `bug tracker
<https://github.com/aio-libs/aiohttp/issues>`_ if you have found a bug
or have some suggestion in order to improve the library.

The library uses `Azure Pipelines <https://dev.azure.com/aio-libs/aiohttp/_build>`_ for
Continuous Integration.


Dependencies
============

- Python 3.6+
- *async_timeout*
- *attrs*
- *chardet*
- *multidict*
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


Communication channels
======================

*aio-libs discourse group*: https://aio-libs.discourse.group

Feel free to post your questions and ideas here.

*gitter chat* https://gitter.im/aio-libs/Lobby

We support `Stack Overflow
<https://stackoverflow.com/questions/tagged/aiohttp>`_.
Please add *aiohttp* tag to your question there.

Contributing
============

Please read the :ref:`instructions for contributors<aiohttp-contributing>`
before making a Pull Request.


Authors and License
===================

The ``aiohttp`` package is written mostly by Nikolay Kim and Andrew Svetlov.

It's *Apache 2* licensed and freely available.

Feel free to improve this package and send a pull request to GitHub_.


.. _aiohttp-backward-compatibility-policy:

Policy for Backward Incompatible Changes
========================================

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


Table Of Contents
=================

.. toctree::
   :name: mastertoc
   :maxdepth: 2

   client
   web
   utilities
   faq
   misc
   external
   contributing
