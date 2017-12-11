.. _aiohttp-client-quickstart:

Client Quickstart
=================

.. currentmodule:: aiohttp

Eager to get started? This page gives a good introduction in how to
get started with aiohttp client API.

First, make sure that aiohttp is :ref:`installed
<aiohttp-installation>` and *up-to-date*

Let's get started with some simple examples.



Make a Request
--------------

Begin by importing the aiohttp module::

    import aiohttp

Now, let's try to get a web-page. For example let's get GitHub's public
time-line::

    async with aiohttp.ClientSession() as session:
        async with session.get('https://api.github.com/events') as resp:
            print(resp.status)
            print(await resp.text())

Now, we have a :class:`ClientSession` called ``session`` and
a :class:`ClientResponse` object called ``resp``. We can get all the
information we need from the response.  The mandatory parameter of
:meth:`ClientSession.get` coroutine is an HTTP url.

In order to make an HTTP POST request use :meth:`ClientSession.post` coroutine::

    session.post('http://httpbin.org/post', data=b'data')

Other HTTP methods are available as well::

    session.put('http://httpbin.org/put', data=b'data')
    session.delete('http://httpbin.org/delete')
    session.head('http://httpbin.org/get')
    session.options('http://httpbin.org/get')
    session.patch('http://httpbin.org/patch', data=b'data')

.. note::

   Don't create a session per request. Most likely you need a session
   per application which performs all requests altogether.

   A session contains a connection pool inside. Connection reusage and
   keep-alives (both are on by default) may speed up total performance.


Passing Parameters In URLs
--------------------------

You often want to send some sort of data in the URL's query string. If
you were constructing the URL by hand, this data would be given as key/value
pairs in the URL after a question mark, e.g. ``httpbin.org/get?key=val``.
Requests allows you to provide these arguments as a :class:`dict`, using the
``params`` keyword argument. As an example, if you wanted to pass
``key1=value1`` and ``key2=value2`` to ``httpbin.org/get``, you would use the
following code::

    params = {'key1': 'value1', 'key2': 'value2'}
    async with session.get('http://httpbin.org/get',
                           params=params) as resp:
        assert str(resp.url) == 'http://httpbin.org/get?key2=value2&key1=value1'

You can see that the URL has been correctly encoded by printing the URL.

For sending data with multiple values for the same key
:class:`MultiDict` may be used as well.


It is also possible to pass a list of 2 item tuples as parameters, in
that case you can specify multiple values for each key::

    params = [('key', 'value1'), ('key', 'value2')]
    async with session.get('http://httpbin.org/get',
                           params=params) as r:
        assert str(r.url) == 'http://httpbin.org/get?key=value2&key=value1'

You can also pass :class:`str` content as param, but beware -- content
is not encoded by library. Note that ``+`` is not encoded::

    async with session.get('http://httpbin.org/get',
                           params='key=value+1') as r:
            assert str(r.url) == 'http://httpbin.org/get?key=value+1'

.. note::

   *aiohttp* internally performs URL canonization before sending request.

   Canonization encodes *host* part by :term:`IDNA` codec and applies
   :term:`requoting` to *path* and *query* parts.

   For example ``URL('http://example.com/путь%30?a=%31')`` is converted to
   ``URL('http://example.com/%D0%BF%D1%83%D1%82%D1%8C/0?a=1')``.

   Sometimes canonization is not desirable if server accepts exact
   representation and does not requote URL itself.

   To disable canonization use ``encoded=True`` parameter for URL construction::

      await session.get(URL('http://example.com/%30', encoded=True))

.. warning::

   Passing *params* overrides ``encoded=True``, never use both options.

Response Content and Status Code
--------------------------------

We can read the content of the server's response and it's status
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
-----------------------

You can also access the response body as bytes, for non-text requests::

    print(await resp.read())

::

    b'[{"created_at":"2015-06-12T14:06:22Z","public":true,"actor":{...

The ``gzip`` and ``deflate`` transfer-encodings are automatically
decoded for you.

You can enable ``brotli`` transfer-encodings support,
just install  `brotlipy <https://github.com/python-hyper/brotlipy>`_.

JSON Request
------------

Any of session's request methods like :func:`request`,
:meth:`ClientSession.get`, :meth:`ClientSesssion.post` etc. accept
`json` parameter::

  async with aiohttp.ClientSession() as session:
      async with session.post(url, json={'test': 'object'})


By default session uses python's standard :mod:`json` module for
serialization.  But it is possible to use different
``serializer``. :class:`ClientSession` accepts ``json_serialize``
parameter::

  import ujson

  async with aiohttp.ClientSession(json_serialize=ujson.dumps) as session:
      async with session.post(url, json={'test': 'object'})

.. note::

   ``ujson`` library is faster than standard :mod:`json` but slightly
   incompatible.

JSON Response Content
---------------------

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
--------------------------

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
        while True:
            chunk = await resp.content.read(chunk_size)
            if not chunk:
                break
            fd.write(chunk)

It is not possible to use :meth:`~ClientResponse.read`,
:meth:`~ClientResponse.json` and :meth:`~ClientResponse.text` after
explicit reading from :attr:`~ClientResponse.content`.

More complicated POST requests
------------------------------

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

To send text with appropriate content-type just use ``text`` attribute ::

    async with session.post(url, text='Тест') as resp:
        ...

POST a Multipart-Encoded File
-----------------------------

To upload Multipart-encoded files::

    url = 'http://httpbin.org/post'
    files = {'file': open('report.xls', 'rb')}

    await session.post(url, data=files)

You can set the ``filename`` and ``content_type`` explicitly::

    url = 'http://httpbin.org/post'
    data = FormData()
    data.add_field('file',
                   open('report.xls', 'rb'),
                   filename='report.xls',
                   content_type='application/vnd.ms-excel')

    await session.post(url, data=data)

If you pass a file object as data parameter, aiohttp will stream it to
the server automatically. Check :class:`~aiohttp.streams.StreamReader`
for supported format information.

.. seealso:: :ref:`aiohttp-multipart`


Streaming uploads
-----------------

:mod:`aiohttp` supports multiple types of streaming uploads, which allows you to
send large files without reading them into memory.

As a simple case, simply provide a file-like object for your body::

    with open('massive-body', 'rb') as f:
       await session.post('http://httpbin.org/post', data=f)


Or you can use :class:`aiohttp.streamer` decorator::

  @aiohttp.streamer
  def file_sender(writer, file_name=None):
      with open(file_name, 'rb') as f:
          chunk = f.read(2**16)
          while chunk:
              yield from writer.write(chunk)
              chunk = f.read(2**16)

  # Then you can use file_sender as a data provider:

  async with session.post('http://httpbin.org/post',
                          data=file_sender(file_name='huge_file')) as resp:
      print(await resp.text())

Also it is possible to use a :class:`~aiohttp.streams.StreamReader`
object. Lets say we want to upload a file from another request and
calculate the file SHA1 hash::

   async def feed_stream(resp, stream):
       h = hashlib.sha256()

       while True:
           chunk = await resp.content.readany()
           if not chunk:
               break
           h.update(chunk)
           stream.feed_data(chunk)

       return h.hexdigest()

   resp = session.get('http://httpbin.org/post')
   stream = StreamReader()
   loop.create_task(session.post('http://httpbin.org/post', data=stream))

   file_hash = await feed_stream(resp, stream)


Because the response content attribute is a
:class:`~aiohttp.streams.StreamReader`, you can chain get and post
requests together::

   r = await session.get('http://python.org')
   await session.post('http://httpbin.org/post',
                      data=r.content)


.. _aiohttp-client-websockets:


WebSockets
----------

:mod:`aiohttp` works with client websockets out-of-the-box.

You have to use the :meth:`aiohttp.ClientSession.ws_connect` coroutine
for client websocket connection. It accepts a *url* as a first
parameter and returns :class:`ClientWebSocketResponse`, with that
object you can communicate with websocket server using response's
methods::

   session = aiohttp.ClientSession()
   async with session.ws_connect('http://example.org/websocket') as ws:

       async for msg in ws:
           if msg.type == aiohttp.WSMsgType.TEXT:
               if msg.data == 'close cmd':
                   await ws.close()
                   break
               else:
                   await ws.send_str(msg.data + '/answer')
           elif msg.type == aiohttp.WSMsgType.CLOSED:
               break
           elif msg.type == aiohttp.WSMsgType.ERROR:
               break


You **must** use the only websocket task for both reading (e.g. ``await
ws.receive()`` or ``async for msg in ws:``) and writing but may have
multiple writer tasks which can only send data asynchronously (by
``await ws.send_str('data')`` for example).



Timeouts
--------

By default all IO operations have 5min timeout. The timeout may be
overridden by passing ``timeout`` parameter into
:meth:`ClientSession.get` and family::

    async with session.get('https://github.com', timeout=60) as r:
        ...

``None`` or ``0`` disables timeout check.

The example wraps a client call in :func:`async_timeout.timeout` context
manager, adding timeout for both connecting and response body
reading procedures::

    import async_timeout

    with async_timeout.timeout(0.001):
        async with session.get('https://github.com') as r:
            await r.text()


.. note::

   Timeout is cumulative time, it includes all operations like sending request,
   redirects, response parsing, consuming response, etc.
