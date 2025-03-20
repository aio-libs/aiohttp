.. currentmodule:: aiohttp

.. _aiohttp-client-quickstart:

===================
 Client Quickstart
===================

Eager to get started? This page gives a good introduction in how to
get started with aiohttp client API.

First, make sure that aiohttp is :ref:`installed
<aiohttp-installation>` and *up-to-date*

Let's get started with some simple examples.



Make a Request
==============

Begin by importing the aiohttp module, and asyncio::

    import aiohttp
    import asyncio

Now, let's try to get a web-page. For example let's query
``http://httpbin.org/get``::

    async def main():
        async with aiohttp.ClientSession() as session:
            async with session.get('http://httpbin.org/get') as resp:
                print(resp.status)
                print(await resp.text())

    asyncio.run(main())

Now, we have a :class:`ClientSession` called ``session`` and a
:class:`ClientResponse` object called ``resp``. We can get all the
information we need from the response.  The mandatory parameter of
:meth:`ClientSession.get` coroutine is an HTTP *url* (:class:`str` or
class:`yarl.URL` instance).

In order to make an HTTP POST request use :meth:`ClientSession.post` coroutine::

    session.post('http://httpbin.org/post', data=b'data')

Other HTTP methods are available as well::

    session.put('http://httpbin.org/put', data=b'data')
    session.delete('http://httpbin.org/delete')
    session.head('http://httpbin.org/get')
    session.options('http://httpbin.org/get')
    session.patch('http://httpbin.org/patch', data=b'data')

To make several requests to the same site more simple, the parameter ``base_url``
of :class:`ClientSession` constructor can be used. For example to request different
endpoints of ``http://httpbin.org`` can be used the following code::

    async with aiohttp.ClientSession('http://httpbin.org') as session:
        async with session.get('/get'):
            pass
        async with session.post('/post', data=b'data'):
            pass
        async with session.put('/put', data=b'data'):
            pass

.. note::

   Don't create a session per request. Most likely you need a session
   per application which performs all requests together.

   More complex cases may require a session per site, e.g. one for
   Github and other one for Facebook APIs. Anyway making a session for
   every request is a **very bad** idea.

   A session contains a connection pool inside. Connection reusage and
   keep-alive (both are on by default) may speed up total performance.

   You may find more information about creating persistent sessions
   in :ref:`aiohttp-persistent-session`.

A session context manager usage is not mandatory
but ``await session.close()`` method
should be called in this case, e.g.::

    session = aiohttp.ClientSession()
    async with session.get('...'):
        # ...
    await session.close()


Passing Parameters In URLs
==========================

You often want to send some sort of data in the URL's query string. If
you were constructing the URL by hand, this data would be given as key/value
pairs in the URL after a question mark, e.g. ``httpbin.org/get?key=val``.
aiohttp allows you to provide these arguments as a :class:`dict`, using the
``params`` keyword argument. As an example, if you wanted to pass
``key1=value1`` and ``key2=value2`` to ``httpbin.org/get``, you would use the
following code::

    params = {'key1': 'value1', 'key2': 'value2'}
    async with session.get('http://httpbin.org/get',
                           params=params) as resp:
        expect = 'http://httpbin.org/get?key1=value1&key2=value2'
        assert str(resp.url) == expect

You can see that the URL has been correctly encoded by printing the URL.

For sending data with multiple values for the same key
:class:`~multidict.MultiDict` may be used; the library support nested lists
(``{'key': ['value1', 'value2']}``) alternative as well.

It is also possible to pass a list of 2 item tuples as parameters, in
that case you can specify multiple values for each key::

    params = [('key', 'value1'), ('key', 'value2')]
    async with session.get('http://httpbin.org/get',
                           params=params) as r:
        expect = 'http://httpbin.org/get?key=value2&key=value1'
        assert str(r.url) == expect

You can also pass :class:`str` content as param, but beware -- content
is not encoded by library. Note that ``+`` is not encoded::

    async with session.get('http://httpbin.org/get',
                           params='key=value+1') as r:
            assert str(r.url) == 'http://httpbin.org/get?key=value+1'

.. note::

   *aiohttp* internally performs URL canonicalization before sending request.

   Canonicalization encodes *host* part by :term:`IDNA` codec and applies
   :term:`requoting` to *path* and *query* parts.

   For example ``URL('http://example.com/путь/%30?a=%31')`` is converted to
   ``URL('http://example.com/%D0%BF%D1%83%D1%82%D1%8C/0?a=1')``.

   Sometimes canonicalization is not desirable if server accepts exact
   representation and does not requote URL itself.

   To disable canonicalization use ``encoded=True`` parameter for URL construction::

      await session.get(
          URL('http://example.com/%30', encoded=True))

.. warning::

   Passing *params* overrides ``encoded=True``, never use both options.

Response Content and Status Code
================================

We can read the content of the server's response and its status
code. Consider the GitHub time-line again::

    async with session.get('https://api.github.com/events') as resp:
        print(resp.status)
        print(await resp.text())

prints out something like::

    200
    '[{"created_at":"2015-06-12T14:06:22Z","public":true,"actor":{...

``aiohttp`` automatically decodes the content from the server. You can
specify custom encoding for the :meth:`~ClientResponse.text` method::

    await resp.text(encoding='windows-1251')


Binary Response Content
=======================

You can also access the response body as bytes, for non-text requests::

    print(await resp.read())

::

    b'[{"created_at":"2015-06-12T14:06:22Z","public":true,"actor":{...

The ``gzip`` and ``deflate`` transfer-encodings are automatically
decoded for you.

You can enable ``brotli`` transfer-encodings support,
just install `Brotli <https://pypi.org/project/Brotli/>`_
or `brotlicffi <https://pypi.org/project/brotlicffi/>`_.

JSON Request
============

Any of session's request methods like :func:`request`,
:meth:`ClientSession.get`, :meth:`ClientSession.post` etc. accept
`json` parameter::

  async with aiohttp.ClientSession() as session:
      await session.post(url, json={'test': 'object'})


By default session uses python's standard :mod:`json` module for
serialization.  But it is possible to use different
``serializer``. :class:`ClientSession` accepts ``json_serialize``
parameter::

  import ujson

  async with aiohttp.ClientSession(
          json_serialize=ujson.dumps) as session:
      await session.post(url, json={'test': 'object'})

.. note::

   ``ujson`` library is faster than standard :mod:`json` but slightly
   incompatible.

JSON Response Content
=====================

There's also a built-in JSON decoder, in case you're dealing with JSON data::

    async with session.get('https://api.github.com/events') as resp:
        print(await resp.json())

In case that JSON decoding fails, :meth:`~ClientResponse.json` will
raise an exception. It is possible to specify custom encoding and
decoder functions for the :meth:`~ClientResponse.json` call.

.. note::

    The methods above reads the whole response body into memory. If you are
    planning on reading lots of data, consider using the streaming response
    method documented below.


Streaming Response Content
==========================

While methods :meth:`~ClientResponse.read`,
:meth:`~ClientResponse.json` and :meth:`~ClientResponse.text` are very
convenient you should use them carefully. All these methods load the
whole response in memory.  For example if you want to download several
gigabyte sized files, these methods will load all the data in
memory. Instead you can use the :attr:`~ClientResponse.content`
attribute. It is an instance of the :class:`aiohttp.StreamReader`
class. The ``gzip`` and ``deflate`` transfer-encodings are
automatically decoded for you::

    async with session.get('https://api.github.com/events') as resp:
        await resp.content.read(10)

In general, however, you should use a pattern like this to save what is being
streamed to a file::

    with open(filename, 'wb') as fd:
        async for chunk in resp.content.iter_chunked(chunk_size):
            fd.write(chunk)

It is not possible to use :meth:`~ClientResponse.read`,
:meth:`~ClientResponse.json` and :meth:`~ClientResponse.text` after
explicit reading from :attr:`~ClientResponse.content`.

More complicated POST requests
==============================

Typically, you want to send some form-encoded data -- much like an HTML form.
To do this, simply pass a dictionary to the *data* argument. Your
dictionary of data will automatically be form-encoded when the request is made::

    payload = {'key1': 'value1', 'key2': 'value2'}
    async with session.post('http://httpbin.org/post',
                            data=payload) as resp:
        print(await resp.text())

::

    {
      ...
      "form": {
        "key2": "value2",
        "key1": "value1"
      },
      ...
    }

If you want to send data that is not form-encoded you can do it by
passing a :class:`bytes` instead of a :class:`dict`. This data will be
posted directly and content-type set to 'application/octet-stream' by
default::

    async with session.post(url, data=b'\x00Binary-data\x00') as resp:
        ...

If you want to send JSON data::

    async with session.post(url, json={'example': 'test'}) as resp:
        ...

To send text with appropriate content-type just use ``data`` argument::

    async with session.post(url, data='Тест') as resp:
        ...

POST a Multipart-Encoded File
=============================

To upload Multipart-encoded files::

    url = 'http://httpbin.org/post'
    files = {'file': open('report.xls', 'rb')}

    await session.post(url, data=files)

You can set the ``filename`` and ``content_type`` explicitly::

    url = 'http://httpbin.org/post'
    data = aiohttp.FormData()
    data.add_field('file',
                   open('report.xls', 'rb'),
                   filename='report.xls',
                   content_type='application/vnd.ms-excel')

    await session.post(url, data=data)

If you pass a file object as data parameter, aiohttp will stream it to
the server automatically. Check :class:`~aiohttp.StreamReader`
for supported format information.

.. seealso:: :ref:`aiohttp-multipart`


Streaming uploads
=================

:mod:`aiohttp` supports multiple types of streaming uploads, which allows you to
send large files without reading them into memory.

As a simple case, simply provide a file-like object for your body::

    with open('massive-body', 'rb') as f:
       await session.post('http://httpbin.org/post', data=f)


Or you can use *asynchronous generator*::

  async def file_sender(file_name=None):
      async with aiofiles.open(file_name, 'rb') as f:
          chunk = await f.read(64*1024)
          while chunk:
              yield chunk
              chunk = await f.read(64*1024)

  # Then you can use file_sender as a data provider:

  async with session.post('http://httpbin.org/post',
                          data=file_sender(file_name='huge_file')) as resp:
      print(await resp.text())


Because the :attr:`~aiohttp.ClientResponse.content` attribute is a
:class:`~aiohttp.StreamReader` (provides async iterator protocol), you
can chain get and post requests together::

   resp = await session.get('http://python.org')
   await session.post('http://httpbin.org/post',
                      data=resp.content)

.. _aiohttp-client-websockets:


WebSockets
==========

:mod:`aiohttp` works with client websockets out-of-the-box.

You have to use the :meth:`aiohttp.ClientSession.ws_connect` coroutine
for client websocket connection. It accepts a *url* as a first
parameter and returns :class:`ClientWebSocketResponse`, with that
object you can communicate with websocket server using response's
methods::

   async with session.ws_connect('http://example.org/ws') as ws:
       async for msg in ws:
           if msg.type == aiohttp.WSMsgType.TEXT:
               if msg.data == 'close cmd':
                   await ws.close()
                   break
               else:
                   await ws.send_str(msg.data + '/answer')
           elif msg.type == aiohttp.WSMsgType.ERROR:
               break


You **must** use the only websocket task for both reading (e.g. ``await
ws.receive()`` or ``async for msg in ws:``) and writing but may have
multiple writer tasks which can only send data asynchronously (by
``await ws.send_str('data')`` for example).


.. _aiohttp-client-timeouts:

Timeouts
========

Timeout settings are stored in :class:`ClientTimeout` data structure.

By default *aiohttp* uses a *total* 300 seconds (5min) timeout, it means that the
whole operation should finish in 5 minutes. In order to allow time for DNS fallback,
the default ``sock_connect`` timeout is 30 seconds.

The value could be overridden by *timeout* parameter for the session (specified in seconds)::

    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        ...

Timeout could be overridden for a request like :meth:`ClientSession.get`::

    async with session.get(url, timeout=timeout) as resp:
        ...

Supported :class:`ClientTimeout` fields are:

   ``total``

      The maximal number of seconds for the whole operation including connection
      establishment, request sending and response reading.

   ``connect``

      The maximal number of seconds for
      connection establishment of a new connection or
      for waiting for a free connection from a pool if pool connection
      limits are exceeded.

   ``sock_connect``

      The maximal number of seconds for connecting to a peer for a new connection, not
      given from a pool.

   ``sock_read``

      The maximal number of seconds allowed for period between reading a new
      data portion from a peer.

    ``ceil_threshold``

      The threshold value to trigger ceiling of absolute timeout values.

All fields are floats, ``None`` or ``0`` disables a particular timeout check, see the
:class:`ClientTimeout` reference for defaults and additional details.

Thus the default timeout is::

   aiohttp.ClientTimeout(total=5*60, connect=None,
                         sock_connect=None, sock_read=None, ceil_threshold=5)

.. note::

   *aiohttp* **ceils** timeout if the value is equal or greater than 5
   seconds. The timeout expires at the next integer second greater than
   ``current_time + timeout``.

   The ceiling is done for the sake of optimization, when many concurrent tasks
   are scheduled to wake-up at the almost same but different absolute times. It
   leads to very many event loop wakeups, which kills performance.

   The optimization shifts absolute wakeup times by scheduling them to exactly
   the same time as other neighbors, the loop wakes up once-per-second for
   timeout expiration.

   Smaller timeouts are not rounded to help testing; in the real life network
   timeouts usually greater than tens of seconds. However, the default threshold
   value of 5 seconds can be configured using the ``ceil_threshold`` parameter.
