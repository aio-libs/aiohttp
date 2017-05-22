.. _aiohttp-client:

Client
======

.. module:: aiohttp

.. currentmodule:: aiohttp


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

   A session contains a connection pool inside, connection reusage and
   keep-alives (both are on by default) may speed up total performance.


JSON Request
------------

Any of session's request methods like `request`, `get`, `post` etc accept
`json` parameter::

  async with aiohttp.ClientSession() as session:
      async with session.post(json={'test': 'object})


By default session uses python's standard `json` module for serialization.
But it is possible to use different `serializer`. `ClientSession` accepts `json_serialize`
parameter::

  import ujson

  async with aiohttp.ClientSession(json_serialize=ujson.dumps) as session:
      async with session.post(json={'test': 'object})


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

Response Content
----------------

We can read the content of the server's response. Consider the GitHub time-line
again::

    async with session.get('https://api.github.com/events') as resp:
        print(await resp.text())

will printout something like::

    '[{"created_at":"2015-06-12T14:06:22Z","public":true,"actor":{...

``aiohttp`` will automatically decode the content from the server. You can
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

RequestInfo
-----------

`ClientResponse` object contains :attr:`~ClientResponse.request_info` property,
which contains request fields: `url` and `headers`.
On `raise_for_status` structure is copied to `ClientResponseError` instance.


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

    await session.post(url,
                       data=json.dumps(payload),
                       headers=headers)


Custom Cookies
--------------

To send your own cookies to the server, you can use the *cookies*
parameter of :class:`ClientSession` constructor::

    url = 'http://httpbin.org/cookies'
    cookies = {'cookies_are': 'working'}
    async with ClientSession(cookies=cookies) as session:
        async with session.get(url) as resp:
            assert await resp.json() == {
               "cookies": {"cookies_are": "working"}}

.. note::
   ``httpbin.org/cookies`` endpoint returns request cookies
   in JSON-encoded body.
   To access session cookies see :attr:`ClientSession.cookie_jar`.


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
passing a :class:`str` instead of a :class:`dict`. This data will be
posted directly.

For example, the GitHub API v3 accepts JSON-Encoded POST/PATCH data::

    import json
    url = 'https://api.github.com/some/endpoint'
    payload = {'some': 'data'}

    async with session.post(url, data=json.dumps(payload)) as resp:
        ...


POST a Multipart-Encoded File
-----------------------------

To upload Multipart-encoded files::

    url = 'http://httpbin.org/post'
    files = {'file': open('report.xls', 'rb')}

    await session.post(url, data=files)

You can set the filename, content_type explicitly::

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


Or you can use `aiohttp.streamer` object::

  @aiohttp.streamer
  def file_sender(writer, file_name=None):
      with open(file_name, 'rb') as f:
          chunk = f.read(2**16)
          while chunk:
              yield from writer.write(chunk)
              chunk = f.read(2**16)

  # Then you can use `file_sender` as a data provider:

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


Uploading pre-compressed data
-----------------------------

To upload data that is already compressed before passing it to aiohttp, call
the request function with the used compression algorithm name (usually deflate or zlib)
as the value of the ``Content-Encoding`` header::

    async def my_coroutine(session, headers, my_data):
        data = zlib.compress(my_data)
        headers = {'Content-Encoding': 'deflate'}
        async with session.post('http://httpbin.org/post',
                                data=data,
                                headers=headers)
            pass


.. _aiohttp-client-session:

Keep-Alive, connection pooling and cookie sharing
-------------------------------------------------

:class:`~aiohttp.ClientSession` may be used for sharing cookies
between multiple requests::

    async with aiohttp.ClientSession() as session:
        await session.get(
            'http://httpbin.org/cookies/set?my_cookie=my_value')
        filtered = session.cookie_jar.filter_cookies('http://httpbin.org')
        assert filtered['my_cookie'].value == 'my_value'
        async with session.get('http://httpbin.org/cookies') as r:
            json_body = await r.json()
            assert json_body['cookies']['my_cookie'] == 'my_value'

You also can set default headers for all session requests::

    async with aiohttp.ClientSession(
        headers={"Authorization": "Basic bG9naW46cGFzcw=="}) as session:
        async with session.get("http://httpbin.org/headers") as r:
            json_body = await r.json()
            assert json_body['headers']['Authorization'] == \
                'Basic bG9naW46cGFzcw=='

:class:`~aiohttp.ClientSession` supports keep-alive requests
and connection pooling out-of-the-box.

.. _aiohttp-client-cookie-safety:

Cookie safety
-------------

By default :class:`~aiohttp.ClientSession` uses strict version of
:class:`aiohttp.CookieJar`. :rfc:`2109` explicitly forbids cookie
accepting from URLs with IP address instead of DNS name
(e.g. `http://127.0.0.1:80/cookie`).

It's good but sometimes for testing we need to enable support for such
cookies. It should be done by passing `unsafe=True` to
:class:`aiohttp.CookieJar` constructor::


    jar = aiohttp.CookieJar(unsafe=True)
    session = aiohttp.ClientSession(cookie_jar=jar)


Connectors
----------

To tweak or change *transport* layer of requests you can pass a custom
*connector* to :class:`~aiohttp.ClientSession` and family. For example::

    conn = aiohttp.TCPConnector()
    session = aiohttp.ClientSession(connector=conn)

.. note::

   You can not re-use custom *connector*, *session* object takes ownership
   of the *connector*.

.. seealso:: :ref:`aiohttp-client-reference-connectors` section for
             more information about different connector types and
             configuration options.


Limiting connection pool size
-----------------------------

To limit amount of simultaneously opened connections you can pass *limit*
parameter to *connector*::

    conn = aiohttp.TCPConnector(limit=30)

The example limits total amount of parallel connections to `30`.

The default is `100`.

If you explicitly want not to have limits, pass `0`. For example::

    conn = aiohttp.TCPConnector(limit=0)

To limit amount of simultaneously opened connection to the same
endpoint (``(host, port, is_ssl)`` triple) you can pass *limit_per_host*
parameter to *connector*::

    conn = aiohttp.TCPConnector(limit_per_host=30)

The example limits amount of parallel connections to the same to `30`.

The default is `0` (no limit on per host bases).


Resolving using custom nameservers
----------------------------------

In order to specify the nameservers to when resolving the hostnames,
:term:`aiodns` is required::

    from aiohttp.resolver import AsyncResolver

    resolver = AsyncResolver(nameservers=["8.8.8.8", "8.8.4.4"])
    conn = aiohttp.TCPConnector(resolver=resolver)


SSL control for TCP sockets
---------------------------

:class:`~aiohttp.TCPConnector` constructor accepts mutually
exclusive *verify_ssl* and *ssl_context* params.

By default it uses strict checks for HTTPS protocol. Certification
checks can be relaxed by passing ``verify_ssl=False``::

  conn = aiohttp.TCPConnector(verify_ssl=False)
  session = aiohttp.ClientSession(connector=conn)
  r = await session.get('https://example.com')


If you need to setup custom ssl parameters (use own certification
files for example) you can create a :class:`ssl.SSLContext` instance and
pass it into the connector::

  sslcontext = ssl.create_default_context(
     cafile='/path/to/ca-bundle.crt')
  conn = aiohttp.TCPConnector(ssl_context=sslcontext)
  session = aiohttp.ClientSession(connector=conn)
  r = await session.get('https://example.com')

If you need to verify **client-side** certificates, you can do the same thing as the previous example,
but add another call to ``load_cret_chain`` with the key pair::

  sslcontext = ssl.create_default_context(
     cafile='/path/to/client-side-ca-bundle.crt')
  sslcontext.load_cert_chain('/path/to/client/public/key.pem', '/path/to/client/private/key.pem')
  conn = aiohttp.TCPConnector(ssl_context=sslcontext)
  session = aiohttp.ClientSession(connector=conn)
  r = await session.get('https://server-with-client-side-certificates-validaction.com')


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
:class:`~aiohttp.UnixConnector`::

  conn = aiohttp.UnixConnector(path='/path/to/socket')
  session = aiohttp.ClientSession(connector=conn)


Proxy support
-------------

aiohttp supports proxy. You have to use
:attr:`proxy`::

   async with aiohttp.ClientSession() as session:
       async with session.get("http://python.org",
                              proxy="http://some.proxy.com") as resp:
           print(resp.status)

Contrary to the ``requests`` library, it won't read environment variables by
default. But you can do so by setting :attr:`proxy_from_env` to True.
It will use the ``getproxies()`` method from ``urllib`` and thus read the
value of the ``$url-scheme_proxy`` variable::

   async with aiohttp.ClientSession() as session:
       async with session.get("http://python.org",
                              proxy_from_env=True) as resp:
           print(resp.status)

It also supports proxy authorization::

   async with aiohttp.ClientSession() as session:
       proxy_auth = aiohttp.BasicAuth('user', 'pass')
       async with session.get("http://python.org",
                              proxy="http://some.proxy.com",
                              proxy_auth=proxy_auth) as resp:
           print(resp.status)

Authentication credentials can be passed in proxy URL::

   session.get("http://python.org",
               proxy="http://user:pass@some.proxy.com")


Response Status Codes
---------------------

We can check the response status code::

   async with session.get('http://httpbin.org/get') as resp:
       assert resp.status == 200


Response Headers
----------------

We can view the server's response :attr:`ClientResponse.headers` using
a :class:`CIMultiDictProxy`::

    >>> resp.headers
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

    >>> resp.headers['Content-Type']
    'application/json'

    >>> resp.headers.get('content-type')
    'application/json'

All headers converted from binary data using UTF-8 with
``surrogateescape`` option. That works fine on most cases but
sometimes unconverted data is needed if a server uses nonstandard
encoding. While these headers are malformed from :rfc:`7230`
perspective they are may be retrieved by using
:attr:`ClientResponse.raw_headers` property::

    >>> resp.raw_headers
    ((b'SERVER', b'nginx'),
     (b'DATE', b'Sat, 09 Jan 2016 20:28:40 GMT'),
     (b'CONTENT-TYPE', b'text/html; charset=utf-8'),
     (b'CONTENT-LENGTH', b'12150'),
     (b'CONNECTION', b'keep-alive'))


Response Cookies
----------------

If a response contains some Cookies, you can quickly access them::

    url = 'http://example.com/some/cookie/setting/url'
    async with session.get(url) as resp:
        print(resp.cookies['example_cookie_name'])

.. note::

   Response cookies contain only values, that were in ``Set-Cookie`` headers
   of the **last** request in redirection chain. To gather cookies between all
   redirection requests please use :ref:`aiohttp.ClientSession
   <aiohttp-client-session>` object.


Response History
----------------

If a request was redirected, it is possible to view previous responses using
the :attr:`~ClientResponse.history` attribute::

    >>> resp = await session.get('http://example.com/some/redirect/')
    >>> resp
    <ClientResponse(http://example.com/some/other/url/) [200]>
    >>> resp.history
    (<ClientResponse(http://example.com/some/redirect/) [301]>,)

If no redirects occurred or ``allow_redirects`` is set to ``False``,
history will be an empty sequence.


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
``ws.send_str('data')`` for example).


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

    with async_timeout.timeout(0.001, loop=session.loop):
        async with session.get('https://github.com') as r:
            await r.text()


.. note::

   Timeout is cumulative time, it includes all operations like sending request,
   redirects, response parsing, consuming response, etc.


.. disqus::
  :title: aiohttp client usage
