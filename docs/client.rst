.. _aiohttp-client:

HTTP Client
===========

.. module:: aiohttp

.. currentmodule:: aiohttp


Make a Request
--------------

Begin by importing the aiohttp module::

    import aiohttp

Now, let's try to get a web-page. For example let's get GitHub's public
time-line ::

    r = await aiohttp.get('https://api.github.com/events')

Now, we have a :class:`ClientResponse` object called ``r``. We can get all the
information we need from this object.
The mandatory parameter of :func:`get` coroutine is an HTTP url.

In order to make an HTTP POST request use :func:`post` coroutine::

    r = await aiohttp.post('http://httpbin.org/post', data=b'data')

Other HTTP methods are available as well::

    r = await aiohttp.put('http://httpbin.org/put', data=b'data')
    r = await aiohttp.delete('http://httpbin.org/delete')
    r = await aiohttp.head('http://httpbin.org/get')
    r = await aiohttp.options('http://httpbin.org/get')
    r = await aiohttp.patch('http://httpbin.org/patch', data=b'data')


Passing Parameters In URLs
--------------------------

You often want to send some sort of data in the URL's query string. If
you were constructing the URL by hand, this data would be given as key/value
pairs in the URL after a question mark, e.g. ``httpbin.org/get?key=val``.
Requests allows you to provide these arguments as a dictionary, using the
``params`` keyword argument. As an example, if you wanted to pass
``key1=value1`` and ``key2=value2`` to ``httpbin.org/get``, you would use the
following code::

    payload = {'key1': 'value1', 'key2': 'value2'}
    async with aiohttp.get('http://httpbin.org/get',
                           params=payload) as r:
        assert r.url == 'http://httpbin.org/get?key2=value2&key1=value1'

You can see that the URL has been correctly encoded by printing the URL.


It is also possible to pass a list of 2 item tuples as parameters, in
that case you can specify multiple values for each key::

    payload = [('key', 'value1'), ('key', 'value2')]
    async with aiohttp.get('http://httpbin.org/get',
                           params=payload) as r:
        assert r.url == 'http://httpbin.org/get?key=value2&key=value1'

You can also pass ``str`` content as param, but beware - content is not encoded
by library. Note that ``+`` is not encoded::

    async with aiohttp.get('http://httpbin.org/get',
                            params='key=value+1') as r:
            assert r.url = 'http://httpbin.org/get?key=value+1'

Response Content
----------------

We can read the content of the server's response. Consider the GitHub time-line
again::

    r = await aiohttp.get('https://api.github.com/events')
    print(await r.text())

will printout something like::

    '[{"created_at":"2015-06-12T14:06:22Z","public":true,"actor":{...

``aiohttp`` will automatically decode the content from the server. You can
specify custom encoding for the :meth:`~ClientResponse.text` method::

    await r.text(encoding='windows-1251')


Binary Response Content
-----------------------

You can also access the response body as bytes, for non-text requests::

    print(await r.read())

::

    b'[{"created_at":"2015-06-12T14:06:22Z","public":true,"actor":{...

The ``gzip`` and ``deflate`` transfer-encodings are automatically
decoded for you.


JSON Response Content
---------------------

There's also a built-in JSON decoder, in case you're dealing with JSON data::

    async with aiohttp.get('https://api.github.com/events') as r:
        print(await r.json())

In case that JSON decoding fails, :meth:`~ClientResponse.json` will
raise an exception. It is possible to specify custom encoding and
decoder functions for the :meth:`~ClientResponse.json` call.


Streaming Response Content
--------------------------

While methods :meth:`~ClientResponse.read`,
:meth:`~ClientResponse.json` and :meth:`~ClientResponse.text` are very
convenient you should use them carefully. All these methods load the
whole response in memory.  For example if you want to download several
gigabyte sized files, these methods will load all the data in
memory. Instead you can use the :attr:`~ClientResponse.content`
attribute. It is an instance of the ``aiohttp.StreamReader``
class. The ``gzip`` and ``deflate`` transfer-encodings are
automatically decoded for you::

    async with aiohttp.get('https://api.github.com/events') as r:
        await r.content.read(10)

In general, however, you should use a pattern like this to save what is being
streamed to a file::

    with open(filename, 'wb') as fd:
        while True:
            chunk = await r.content.read(chunk_size)
            if not chunk:
                break
            fd.write(chunk)

It is not possible to use :meth:`~ClientResponse.read`,
:meth:`~ClientResponse.json` and :meth:`~ClientResponse.text` after
explicit reading from :attr:`~ClientResponse.content`.


Releasing Response
--------------------------

Don't forget to release response after use. This will ensure explicit
behavior and proper connection pooling.

The easiest way to correctly response releasing is ``async with`` statement::

    async with client.get(url) as resp:
        pass

But explicit :meth:`~ClientResponse.release` call also may be used::

    await r.release()

But it's not necessary if you use :meth:`~ClientResponse.read`,
:meth:`~ClientResponse.json` and :meth:`~ClientResponse.text` methods.
They do release connection internally but better don't rely on that
behavior.


Custom Headers
--------------

If you need to add HTTP headers to a request, pass them in a
:class:`dict` to the *headers* parameter.

For example, if you want to specify the content-type for the previous
example::

    import json
    url = 'https://api.github.com/some/endpoint'
    payload = {'some': 'data'}
    headers = {'content-type': 'application/json'}

    await aiohttp.post(url,
                       data=json.dumps(payload),
                       headers=headers)


Custom Cookies
--------------

To send your own cookies to the server, you can use the *cookies*
parameter::

    url = 'http://httpbin.org/cookies'
    cookies = dict(cookies_are='working')

    async with aiohttp.get(url, cookies=cookies) as r:
        assert await r.json() == {"cookies": {"cookies_are": "working"}}


More complicated POST requests
------------------------------

Typically, you want to send some form-encoded data — much like an HTML form.
To do this, simply pass a dictionary to the *data* argument. Your
dictionary of data will automatically be form-encoded when the request is made::

    payload = {'key1': 'value1', 'key2': 'value2'}
    async with aiohttp.post('http://httpbin.org/post',
                            data=payload) as r:
        print(await r.text())

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
passing a :class:`str` instead of a :class:`dict`. This data will be
posted directly.

For example, the GitHub API v3 accepts JSON-Encoded POST/PATCH data::

    import json
    url = 'https://api.github.com/some/endpoint'
    payload = {'some': 'data'}

    r = await aiohttp.post(url, data=json.dumps(payload))


POST a Multipart-Encoded File
-----------------------------

To upload Multipart-encoded files::

    url = 'http://httpbin.org/post'
    files = {'file': open('report.xls', 'rb')}

    await aiohttp.post(url, data=files)

You can set the filename, content_type explicitly::

    url = 'http://httpbin.org/post'
    data = FormData()
    data.add_field('file',
                   open('report.xls', 'rb'),
                   filename='report.xls',
                   content_type='application/vnd.ms-excel')

    await aiohttp.post(url, data=data)

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
       await aiohttp.post('http://some.url/streamed', data=f)


Or you can provide an :ref:`coroutine<coroutine>` that yields bytes objects::

   @asyncio.coroutine
   def my_coroutine():
      chunk = yield from read_some_data_from_somewhere()
      if not chunk:
         return
      yield chunk

.. warning:: ``yield`` expression is forbidden inside ``async def``.

.. note::

   It is not a standard :ref:`coroutine<coroutine>` as it yields values so it
   can not be used like ``yield from my_coroutine()``.
   :mod:`aiohttp` internally handles such coroutines.

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
           s.feed_data(chunk)

       return h.hexdigest()

   resp = aiohttp.get('http://httpbin.org/post')
   stream = StreamReader()
   loop.create_task(aiohttp.post('http://httpbin.org/post', data=stream))

   file_hash = await feed_stream(resp, stream)


Because the response content attribute is a
:class:`~aiohttp.streams.StreamReader`, you can chain get and post
requests together (aka HTTP pipelining)::

   r = await aiohttp.request('get', 'http://python.org')
   await aiohttp.post('http://httpbin.org/post',
                      data=r.content)


Uploading pre-compressed data
-----------------------------

To upload data that is already compressed before passing it to aiohttp, call
the request function with ``compress=False`` and set the used compression
algorithm name (usually deflate or zlib) as the value of the
``Content-Encoding`` header::

    @asyncio.coroutine
    def my_coroutine( my_data):
        data = zlib.compress(my_data)
        headers = {'Content-Encoding': 'deflate'}
        yield from aiohttp.post(
            'http://httpbin.org/post', data=data, headers=headers,
            compress=False)


.. _aiohttp-client-session:

Keep-Alive, connection pooling and cookie sharing
-------------------------------------------------

To share cookies between multiple requests you can create an
:class:`~aiohttp.client.ClientSession` object::

    session = aiohttp.ClientSession()
    await session.post(
         'http://httpbin.org/cookies/set/my_cookie/my_value')
    async with session.get('http://httpbin.org/cookies') as r:
        json = await r.json()
        assert json['cookies']['my_cookie'] == 'my_value'

You also can set default headers for all session requests::

    session = aiohttp.ClientSession(
        headers={"Authorization": "Basic bG9naW46cGFzcw=="})
    async with s.get("http://httpbin.org/headers") as r:
        json = yield from r.json()
        assert json['headers']['Authorization'] == 'Basic bG9naW46cGFzcw=='

By default aiohttp does not use connection pooling. In other words
multiple calls to :func:`~aiohttp.client.request` will start a new
connection to host each.  :class:`~aiohttp.client.ClientSession`
object will do connection pooling for you.


Connectors
----------

To tweak or change *transport* layer of requests you can pass a custom
**Connector** to :func:`aiohttp.request` and family. For example::

    conn = aiohttp.TCPConnector()
    r = await aiohttp.get('http://python.org', connector=conn)

:class:`ClientSession` constructor also accepts *connector* instance::

    session = aiohttp.ClientSession(connector=aiohttp.TCPConnector())


Limiting connection pool size
-----------------------------

To limit amount of simultaneously opened connection to the same
endpoint (``(host, port, is_ssl)`` triple) you can pass *limit*
parameter to **connector**::

    conn = aiohttp.TCPConnector(limit=30)

The example limits amount of parallel connections to `30`.


SSL control for TCP sockets
---------------------------

:class:`aiohttp.connector.TCPConnector` constructor accepts mutually
exclusive *verify_ssl* and *ssl_context* params.

By default it uses strict checks for HTTPS protocol. Certification
checks can be relaxed by passing ``verify_ssl=False``::

  conn = aiohttp.TCPConnector(verify_ssl=False)
  session = aiohttp.ClientSession(connector=conn)
  r = await session.get('https://example.com')


If you need to setup custom ssl parameters (use own certification
files for example) you can create a :class:`ssl.SSLContext` instance and
pass it into the connector::

  sslcontext = ssl.create_default_context(cafile='/path/to/ca-bundle.crt')
  conn = aiohttp.TCPConnector(ssl_context=sslcontext)
  session = aiohttp.ClientSession(connector=conn)
  r = await session.get('https://example.com')

You may also verify certificates via MD5, SHA1, or SHA256 fingerprint::

  # Attempt to connect to https://www.python.org
  # with a pin to a bogus certificate:
  bad_md5 = b'\xa2\x06G\xad\xaa\xf5\xd8\\J\x99^by;\x06='
  conn = aiohttp.TCPConnector(fingerprint=bad_md5)
  session = aiohttp.ClientSession(connector=conn)
  exc = None
  try:
      r = yield from session.get('https://www.python.org')
  except FingerprintMismatch as e:
      exc = e
  assert exc is not None
  assert exc.expected == bad_md5

  # www.python.org cert's actual md5
  assert exc.got == b'\xca;I\x9cuv\x8es\x138N$?\x15\xca\xcb'

Note that this is the fingerprint of the DER-encoded certificate.
If you have the certificate in PEM format, you can convert it to
DER with e.g. ``openssl x509 -in crt.pem -inform PEM -outform DER > crt.der``.

Tip: to convert from a hexadecimal digest to a binary byte-string, you can use
:attr:`binascii.unhexlify`::

  md5_hex = 'ca3b499c75768e7313384e243f15cacb'
  from binascii import unhexlify
  assert unhexlify(md5_hex) == b'\xca;I\x9cuv\x8es\x138N$?\x15\xca\xcb'

Unix domain sockets
-------------------

If your HTTP server uses UNIX domain sockets you can use
:class:`aiohttp.connector.UnixConnector`::

  conn = aiohttp.UnixConnector(path='/path/to/socket')
  r = await aiohttp.get('http://python.org', connector=conn)


Proxy support
-------------

aiohttp supports proxy. You have to use
:class:`aiohttp.connector.ProxyConnector`::

   conn = aiohttp.ProxyConnector(proxy="http://some.proxy.com")
   r = await aiohttp.get('http://python.org',
                         connector=conn)

:class:`~aiohttp.connector.ProxyConnector` also supports proxy authorization::

   conn = aiohttp.ProxyConnector(
      proxy="http://some.proxy.com",
      proxy_auth=aiohttp.BasicAuth('user', 'pass'))
   session = aiohttp.ClientSession(connector=conn)
   async with session.get('http://python.org') as r:
       assert r.status == 200

Authentication credentials can be passed in proxy URL::

   conn = aiohttp.ProxyConnector(
       proxy="http://user:pass@some.proxy.com")
   session = aiohttp.ClientSession(connector=conn)
   async with session.get('http://python.org') as r:
       assert r.status == 200


Response Status Codes
---------------------

We can check the response status code::

   async with aiohttp.get('http://httpbin.org/get') as r:
       assert r.status == 200


Response Headers
----------------

We can view the server's response headers using a multidict::

    >>> r.headers
    {'ACCESS-CONTROL-ALLOW-ORIGIN': '*',
     'CONTENT-TYPE': 'application/json',
     'DATE': 'Tue, 15 Jul 2014 16:49:51 GMT',
     'SERVER': 'gunicorn/18.0',
     'CONTENT-LENGTH': '331',
     'CONNECTION': 'keep-alive'}

The dictionary is special, though: it's made just for HTTP
headers. According to `RFC 7230
<http://tools.ietf.org/html/rfc7230#section-3.2>`_, HTTP Header names
are case-insensitive. It also supports multiple values for the same
key as HTTP protocol does.

So, we can access the headers using any capitalization we want::

    >>> r.headers['Content-Type']
    'application/json'

    >>> r.headers.get('content-type')
    'application/json'


Response Cookies
----------------

If a response contains some Cookies, you can quickly access them::

    url = 'http://example.com/some/cookie/setting/url'
    async with aiohttp.get(url) as r:
        print(r.cookies['example_cookie_name'])

.. note::

   Response cookies contain only values, that were in ``Set-Cookie`` headers
   of the **last** request in redirection chain. To gather cookies between all
   redirection requests you can use :ref:`aiohttp.ClientSession
   <aiohttp-client-session>` object.


Response History
----------------

If a request was redirected, it is possible to view previous responses using
the :attr:`~ClientResponse.history` attribute::

    >>> r = await aiohttp.get('http://example.com/some/redirect/')
    >>> r
    <ClientResponse(http://example.com/some/other/url/) [200]>
    >>> r.history
    (<ClientResponse(http://example.com/some/redirect/) [301]>,)

If no redirects occurred or ``allow_redirects`` is set to ``False``,
history will be an empty sequence.


.. _aiohttp-client-websockets:

WebSockets
----------

.. versionadded:: 0.15


:mod:`aiohttp` works with client websockets out-of-the-box.

You have to use the :meth:`aiohttp.ClientSession.ws_connect` coroutine
for client websocket connection. It accepts a *url* as a first
parameter and returns :class:`ClientWebSocketResponse`, with that
object you can communicate with websocket server using response's
methods::

   session = aiohttp.ClientSession()
   async with session.ws_connect('http://example.org/websocket') as ws:

       async for msg in ws:
           if msg.tp == aiohttp.MsgType.text:
               if msg.data == 'close cmd':
                   await ws.close()
                   break
               else:
                   ws.send_str(msg.data + '/answer')
           elif msg.tp == aiohttp.MsgType.closed:
               break
           elif msg.tp == aiohttp.MsgType.error:
               break

If you prefer to establish *websocket client connection* without
explicit :class:`~aiohttp.ClientSession` instance please use
:func:`ws_connect()`::

   async with aiohttp.ws_connect('http://example.org/websocket') as ws:
       ...


You **must** use the only websocket task for both reading (e.g ``await
ws.receive()`` or ``async for msg in ws:``) and writing but may have
multiple writer tasks which can only send data asynchronously (by
``ws.send_str('data')`` for example).


Timeouts
--------

You should use :func:`asyncio.wait_for()` coroutine if you want to limit
time to wait for a response from a server::

    >>> asyncio.wait_for(aiohttp.get('http://github.com'),
    ...                             0.001)
    Traceback (most recent call last)\:
      File "<stdin>", line 1, in <module>
    asyncio.TimeoutError()

Or wrap your client call in :class:`Timeout` context manager::

    with aiohttp.Timeout(0.001):
        async with aiohttp.get('https://github.com') as r:
            await r.text()

.. warning::

    *timeout* is not a time limit on the entire response download;
    rather, an exception is raised if the server has not issued a
    response for *timeout* seconds (more precisely, if no bytes have been
    received on the underlying socket for *timeout* seconds).


.. disqus::
