.. module:: aiohttp.streams

.. _aiohttp-streams:

Streaming API
=============


``aiohttp`` uses streams for retrieving *BODIES*:
:attr:`aiohttp.web.Request.content` and
:attr:`aiohttp.ClientResponse.content` are streams.


StreamReader
------------

.. class:: StreamReader

   .. comethod:: read(n=-1)

   .. comethod:: readany()

   .. comethod:: readexactly(n)

   .. comethod:: readline()

   .. method:: read_nowait(n=None)

   .. comethod:: iter_chunked(n)
      :async-for:

   .. comethod:: iter_any(n)
      :async-for:
