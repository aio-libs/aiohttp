.. currentmodule:: aiohttp

.. _aiohttp-http2:

Client-side HTTP/2 Support
==========================

.. versionadded:: 4.0

aiohttp now includes experimental client-side support for `HTTP/2 <https://www.rfc-editor.org/info/rfc9113/>`_.
This page explains how to enable it, its requirements, and current limitations.

.. note::
   HTTP/2 support is still under active development. Some features may be
   incomplete or behave differently compared to HTTP/1.1.

Requirements
------------

- The ``hpack`` library is required for ``HTTP/2`` support. Install it via ``pip install aiohttp[http2]``.
- HTTP/2 requires TLS and the ``ALPN`` extension. Therefore, you must use an
  ``https://`` URL.

Enabling HTTP/2 on the Client
-----------------------------

To use HTTP/2 in a :class:`ClientSession`, pass ``http2_enabled=True``:

.. code-block:: python

   import aiohttp
   import asyncio

   async def main():
       async with aiohttp.ClientSession(http2_enabled=True) as session:
           async with session.get('https://httpbingo.org') as resp:
               print(resp.version)  # Should print HttpVersion(2, 0)
               print(await resp.text())

   asyncio.run(main())

.. note::
   If the server does not support HTTP/2, the
   connection falls back to HTTP/1.1 automatically.

Client Reference Changes
------------------------

The following additions have been made to :class:`aiohttp.ClientSession`:

- ``http2_enabled``: boolean, default ``False``. When ``True``, enables HTTP/2 support.

For details, see :ref:`aiohttp-client-reference`.

Limitations and Known Issues
-----------------------------

- **No cleartext HTTP/2 (h2c)**.
- **Stream prioritization** is not supported.
- **Server push** is not supported.
- **WebSockets** over HTTP/2 (RFC 8441) are not supported.

To make the most of HTTP/2
--------------------------

Send many requests at once via ``gather`` and retrieve their results eagerly with ``as_completed``.

.. code-block:: python

   import aiohttp
   import asyncio

   async def main():
       async with aiohttp.ClientSession(http2_enabled=True) as session:
           r1 = session.get("https://httpbingo.org/delay/1")
           r2 = session.get("https://httpbingo.org/delay/2")

           for c in asyncio.as_completed([r1, r2]):
               res = await c
               print(res.status, res.version, res.url)

           r3 = session.get("https://httpbingo.org/delay/1")
           r4 = session.get("https://httpbingo.org/delay/2")

           for res in await asyncio.gather(*[r3, r4]):
               print(res.status, res.version, res.url)

   asyncio.run(main())



Additional Resources
--------------------

- `HTTP/2 specification <https://www.rfc-editor.org/info/rfc9113/>`_
- `hpack on GitHub <https://github.com/python-hyper/hpack/>`_
