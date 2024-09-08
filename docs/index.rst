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
  :ref:`aiohttp-web-signals` and pluggable routing.

.. _aiohttp-installation:

Library Installation
====================

.. code-block:: bash

   $ pip install aiohttp

For speeding up DNS resolving by client API you may install
:term:`aiodns` as well.
This option is highly recommended:

.. code-block:: bash

   $ pip install aiodns

Installing all speedups in one command
--------------------------------------

The following will get you ``aiohttp`` along with :term:`aiodns` and ``Brotli`` in one
bundle.
No need to type separate commands anymore!

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

  asyncio.run(main())

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

Development mode
================

When writing your code, we recommend enabling Python's
`development mode <https://docs.python.org/3/library/devmode.html>`_
(``python -X dev``). In addition to the extra features enabled for asyncio, aiohttp
will:

- Use a strict parser in the client code (which can help detect malformed responses
  from a server).
- Enable some additional checks (resulting in warnings in certain situations).

What's new in aiohttp 3?
========================

Go to :ref:`aiohttp_whats_new_3_0` page for aiohttp 3.0 major release
changes.


Tutorial
========

:ref:`Polls tutorial <aiohttpdemos:aiohttp-demos-polls-beginning>`


Source code
===========

The project is hosted on GitHub_

Please feel free to file an issue on the `bug tracker
<https://github.com/aio-libs/aiohttp/issues>`_ if you have found a bug
or have some suggestion in order to improve the library.


Dependencies
============

- *attrs*
- *multidict*
- *yarl*

- *Optional* :term:`aiodns` for fast DNS resolving. The
  library is highly recommended.

  .. code-block:: bash

     $ pip install aiodns

- *Optional* :term:`Brotli` or :term:`brotlicffi` for brotli (:rfc:`7932`)
  client compression support.

  .. code-block:: bash

     $ pip install Brotli


Communication channels
======================

*aio-libs Discussions*: https://github.com/aio-libs/aiohttp/discussions

Feel free to post your questions and ideas here.

*Matrix*: `#aio-libs:matrix.org <https://matrix.to/#/#aio-libs:matrix.org>`_

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
