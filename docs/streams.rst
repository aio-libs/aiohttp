.. module:: aiohttp.streams

.. _aiohttp-streams:

Streaming API
=============

.. module:: aiohttp
.. currentmodule:: aiohttp


``aiohttp`` uses streams for retrieving *BODIES*:
:attr:`aiohttp.web.Request.content` and
:attr:`aiohttp.ClientResponse.content` are properties with stream API.


.. class:: StreamReader

   The reader from incoming stream.

   User should never instantiate streams manually but use existing
   :attr:`aiohttp.web.Request.content` and
   :attr:`aiohttp.ClientResponse.content` properties for accessing raw
   BODY data.

Reading Methods
---------------

.. comethod:: StreamReader.read(n=-1)

   Read up to *n* bytes. If *n* is not provided, or set to ``-1``, read until
   EOF and return all read bytes.

   If the EOF was received and the internal buffer is empty, return an
   empty bytes object.

   :param int n: how many bytes to read, ``-1`` for the whole stream.

   :return bytes: the given data

.. comethod:: StreamReader.readany()

   Read next data portion for the stream.

   Returns immediately if internal buffer has a data.

   :return bytes: the given data

.. comethod:: StreamReader.readexactly(n)

   Read exactly *n* bytes.

   Raise an :exc:`asyncio.IncompleteReadError` if the end of the
   stream is reached before *n* can be read, the
   :attr:`asyncio.IncompleteReadError.partial` attribute of the
   exception contains the partial read bytes.

   :param int n: how many bytes to read.

   :return bytes: the given data


.. comethod:: StreamReader.readline()

   Read one line, where “line” is a sequence of bytes ending
   with ``\n``.

   If EOF is received, and ``\n`` was not found, the method will
   return the partial read bytes.

   If the EOF was received and the internal buffer is empty, return an
   empty bytes object.

   :return bytes: the given line


Asynchronous Iteration Support
------------------------------


Stream reader supports asynchronous iteration over BODY.

By default it iterates over lines::

   async for line in response.content:
       print(line)

Also there are methods for iterating over data chunks with maximum
size limit and over any available data.

.. comethod:: StreamReader.iter_chunked(n)
   :async-for:

   Iterates over data chunks with maximum size limit::

      async for data in response.content.iter_chunked(1024):
          print(data)

.. comethod:: StreamReader.iter_any()
   :async-for:

   Iterates over data chunks in order of intaking them into the stream::

      async for data in response.content.iter_any():
          print(data)

.. comethod:: StreamReader.iter_chunks()
   :async-for:

   Iterates over data chunks as received from the server:: 

      async for data in response.content.iter_chunks():
          print(data)


Helpers
-------

.. method:: StreamReader.exception()

   Get the exception occurred on data reading.

.. method:: is_eof()

   Return ``True`` if EOF was reached.

   Internal buffer may be not empty at the moment.

   .. seealso::

      :meth:`StreamReader.at_eof()`

.. method:: StreamReader.at_eof()

   Return ``True`` if the buffer is empty and EOF was reached.

.. method:: StreamReader.read_nowait(n=None)

   Returns data from internal buffer if any, empty bytes object otherwise.

   Raises :exc:`RuntimeError` if other coroutine is waiting for stream.


   :param int n: how many bytes to read, ``-1`` for the whole internal
                 buffer.

   :return bytes: the given data

.. method:: StreamReader.unread_data(data)

   Rollback reading some data from stream, inserting it to buffer head.

   :param bytes data: data to push back into the stream.

   .. warning:: The method does not wake up waiters.

      E.g. :meth:`~StreamReader.read()` will not be resumed.


.. comethod:: wait_eof()

   Wait for EOF. The given data may be accessible by upcoming read calls.


.. disqus::
  :title: aiohttp streaming api
