==================================
Async http client/server framework
==================================

.. image:: https://raw.githubusercontent.com/aio-libs/aiohttp/master/docs/aiohttp-plain.svg
   :height: 64px
   :width: 64px
   :alt: aiohttp logo

|

.. image:: https://github.com/aio-libs/aiohttp/workflows/CI/badge.svg
   :target: https://github.com/aio-libs/aiohttp/actions?query=workflow%3ACI
   :alt: GitHub Actions status for master branch

.. image:: https://codecov.io/gh/aio-libs/aiohttp/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/aio-libs/aiohttp
   :alt: codecov.io status for master branch

.. image:: https://badge.fury.io/py/aiohttp.svg
   :target: https://pypi.org/project/aiohttp
   :alt: Latest PyPI package version

.. image:: https://img.shields.io/pypi/dm/aiohttp
   :target: https://pypistats.org/packages/aiohttp
   :alt: Downloads count

.. image:: https://readthedocs.org/projects/aiohttp/badge/?version=latest
   :target: https://docs.aiohttp.org/
   :alt: Latest Read The Docs

.. image:: https://img.shields.io/discourse/status?server=https%3A%2F%2Faio-libs.discourse.group
   :target: https://aio-libs.discourse.group
   :alt: Discourse status

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :target: https://gitter.im/aio-libs/Lobby
   :alt: Chat on Gitter


Key Features
============

- Supports both client and server side of HTTP protocol.
- Supports both client and server Web-Sockets out-of-the-box and avoids
  Callback Hell.
- Provides Web-server with middlewares and plugable routing.


Getting started
===============

Client
------

To get something from the web:

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

.. code-block::

    Status: 200
    Content-type: text/html; charset=utf-8
    Body: <!doctype html> ...

Coming from `requests <https://requests.readthedocs.io/>`_ ? Read `why we need so many lines <https://aiohttp.readthedocs.io/en/latest/http_request_lifecycle.html>`_.

Server
------

An example using a simple server:

.. code-block:: python

    # examples/server_simple.py
    from aiohttp import web

    async def handle(request):
        name = request.match_info.get('name', "Anonymous")
        text = "Hello, " + name
        return web.Response(text=text)

    async def wshandle(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.type == web.WSMsgType.text:
                await ws.send_str("Hello, {}".format(msg.data))
            elif msg.type == web.WSMsgType.binary:
                await ws.send_bytes(msg.data)
            elif msg.type == web.WSMsgType.close:
                break

        return ws


    app = web.Application()
    app.add_routes([web.get('/', handle),
                    web.get('/echo', wshandle),
                    web.get('/{name}', handle)])

    if __name__ == '__main__':
        web.run_app(app)


Documentation
=============

https://aiohttp.readthedocs.io/


Demos
=====

https://github.com/aio-libs/aiohttp-demos


External links
==============

* `Third party libraries
  <http://aiohttp.readthedocs.io/en/latest/third_party.html>`_
* `Built with aiohttp
  <http://aiohttp.readthedocs.io/en/latest/built_with.html>`_
* `Powered by aiohttp
  <http://aiohttp.readthedocs.io/en/latest/powered_by.html>`_

Feel free to make a Pull Request for adding your link to these pages!


Communication channels
======================

*aio-libs discourse group*: https://aio-libs.discourse.group

*gitter chat* https://gitter.im/aio-libs/Lobby

We support `Stack Overflow
<https://stackoverflow.com/questions/tagged/aiohttp>`_.
Please add *aiohttp* tag to your question there.

Requirements
============

- Python >= 3.7
- async-timeout_
- attrs_
- chardet_
- multidict_
- yarl_

Optionally you may install the cChardet_ and aiodns_ libraries (highly
recommended for sake of speed).

.. _chardet: https://pypi.python.org/pypi/chardet
.. _aiodns: https://pypi.python.org/pypi/aiodns
.. _attrs: https://github.com/python-attrs/attrs
.. _multidict: https://pypi.python.org/pypi/multidict
.. _yarl: https://pypi.python.org/pypi/yarl
.. _async-timeout: https://pypi.python.org/pypi/async_timeout
.. _cChardet: https://pypi.python.org/pypi/cchardet

License
=======

``aiohttp`` is offered under the Apache 2 license.


Keepsafe
========

The aiohttp community would like to thank Keepsafe
(https://www.getkeepsafe.com) for its support in the early days of
the project.


Source code
===========

The latest developer version is available in a GitHub repository:
https://github.com/aio-libs/aiohttp

Benchmarks
==========

If you are interested in efficiency, the AsyncIO community maintains a
list of benchmarks on the official wiki:
https://github.com/python/asyncio/wiki/Benchmarks
