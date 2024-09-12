.. _aiohttp-streams:

Streaming API
=============

.. currentmodule:: aiohttp


``aiohttp`` uses streams for retrieving *BODIES*:
:attr:`aiohttp.web.BaseRequest.content` and
:attr:`aiohttp.ClientResponse.content` are properties with stream API.


.. class:: StreamReader

   The reader from incoming stream.

   User should never instantiate streams manually but use existing
   :attr:`aiohttp.web.BaseRequest.content` and
   :attr:`aiohttp.ClientResponse.content` properties for accessing raw
   BODY data.

Reading Methods
---------------

.. method:: StreamReader.read(n=-1)
      :async:

   Read up to a maximum of *n* bytes. If *n* is not provided, or set to ``-1``,
   read until EOF and return all read bytes.

   When *n* is provided, data will be returned as soon as it is available.
   Therefore it will return less than *n* bytes if there are less than *n*
   bytes in the buffer.

   If the EOF was received and the internal buffer is empty, return an
   empty bytes object.

   :param int n: maximum number of bytes to read, ``-1`` for the whole stream.

   :return bytes: the given data

.. method:: StreamReader.readany()
      :async:

   Read next data portion for the stream.

   Returns immediately if internal buffer has a data.

   :return bytes: the given data

.. method:: StreamReader.readexactly(n)
      :async:

   Read exactly *n* bytes.

   Raise an :exc:`asyncio.IncompleteReadError` if the end of the
   stream is reached before *n* can be read, the
   :attr:`asyncio.IncompleteReadError.partial` attribute of the
   exception contains the partial read bytes.

   :param int n: how many bytes to read.

   :return bytes: the given data


.. method:: StreamReader.readline()
      :async:

   Read one line, where “line” is a sequence of bytes ending
   with ``\n``.

   If EOF is received, and ``\n`` was not found, the method will
   return the partial read bytes.

   If the EOF was received and the internal buffer is empty, return an
   empty bytes object.

   :return bytes: the given line

.. method:: StreamReader.readuntil(separator="\n")
      :async:

   Read until separator, where `separator` is a sequence of bytes.

   If EOF is received, and `separator` was not found, the method will
   return the partial read bytes.

   If the EOF was received and the internal buffer is empty, return an
   empty bytes object.

   .. versionadded:: 3.8

   :return bytes: the given data

.. method:: StreamReader.readchunk()
      :async:

   Read a chunk of data as it was received by the server.

   Returns a tuple of (data, end_of_HTTP_chunk).

   When chunked transfer encoding is used, end_of_HTTP_chunk is a :class:`bool`
   indicating if the end of the data corresponds to the end of a HTTP chunk,
   otherwise it is always ``False``.

   :return tuple[bytes, bool]: a chunk of data and a :class:`bool` that is ``True``
                               when the end of the returned chunk corresponds
                               to the end of a HTTP chunk.


Asynchronous Iteration Support
------------------------------


Stream reader supports asynchronous iteration over BODY.

By default it iterates over lines::

   async for line in response.content:
       print(line)

Also there are methods for iterating over data chunks with maximum
size limit and over any available data.

.. method:: StreamReader.iter_chunked(n)
   :async:

   Iterates over data chunks with maximum size limit::

      async for data in response.content.iter_chunked(1024):
          print(data)

   To get chunks that are exactly *n* bytes, you could use the
   `asyncstdlib.itertools <https://asyncstdlib.readthedocs.io/en/stable/source/api/itertools.html>`_
   module::

      chunks = batched(chain.from_iterable(response.content.iter_chunked(n)), n)
      async for data in chunks:
          print(data)

.. method:: StreamReader.iter_any()
   :async:

   Iterates over data chunks in order of intaking them into the stream::

      async for data in response.content.iter_any():
          print(data)

.. method:: StreamReader.iter_chunks()
   :async:

   Iterates over data chunks as received from the server::

      async for data, _ in response.content.iter_chunks():
          print(data)

   If chunked transfer encoding is used, the original http chunks formatting
   can be retrieved by reading the second element of returned tuples::

      buffer = b""

      async for data, end_of_http_chunk in response.content.iter_chunks():
          buffer += data
          if end_of_http_chunk:
              print(buffer)
              buffer = b""


Helpers
-------

.. method:: StreamReader.exception()

   Get the exception occurred on data reading.

.. method:: is_eof()

   Return ``True`` if EOF was reached.

   Internal buffer may be not empty at the moment.

   .. seealso::

      :meth:`StreamReader.at_eof`

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

      E.g. :meth:`~StreamReader.read` will not be resumed.


.. method:: wait_eof()
      :async:

   Wait for EOF. The given data may be accessible by upcoming read calls.
