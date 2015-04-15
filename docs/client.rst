.. _aiohttp-client:

HTTP Client
===========

.. highlight:: python

.. module:: aiohttp.client

Example
-------

Because most of the *aiohttp* methods are generators, they will not work
in the interactive python interpreter like regular functions
would. For convenience, we show our examples as if they were run in
the interactive interpreter, but please remember that actually running
them requires that you wrap them in functions and run them with an
:ref:`asyncio loop<asyncio-event-loop>`. For example::

  >>> def run():
  ...   r = yield from aiohttp.request('get', 'http://python.org')
  ...   raw = yield from r.text()
  ...   print(raw)

  >>> if __name__ == '__main__':
  ...    asyncio.get_event_loop().run_until_complete(run())



Make a Request
--------------

Begin by importing the aiohttp module::

    >>> import aiohttp

Now, let's try to get a webpage. For example let's get GitHub's public
timeline ::

    >>> r = yield from aiohttp.request(
    ...     'get', 'https://github.com/timeline.json')

Now, we have a :class:`ClientResponse` object called ``r``. We can get all the
information we need from this object.
The first parameter is the http method, in that case it is ``get``
and the second is an http url.
In order to make an HTTP POST request::

    >>> r = yield from aiohttp.request(
    ...     'post', 'http://httpbin.org/post')

The first parameter could be any valid http method. For example::

    >>> r = yield from aiohttp.request(
    ...     'put', 'http://httpbin.org/put')
    >>> r = yield from aiohttp.request(
    ...     'delete', 'http://httpbin.org/delete')
    >>> r = yield from aiohttp.request(
    ...     'head', 'http://httpbin.org/get')
    >>> r = yield from aiohttp.request(
    ...     'options', 'http://httpbin.org/get')
    >>> r = yield from aiohttp.request(
    ...     'patch', 'http://httpbin.org/patch')


Passing Parameters In URLs
--------------------------

You often want to send some sort of data in the URL's query string. If
you were constructing the URL by hand, this data would be given as key/value
pairs in the URL after a question mark, e.g. ``httpbin.org/get?key=val``.
Requests allows you to provide these arguments as a dictionary, using the
``params`` keyword argument. As an example, if you wanted to pass
``key1=value1`` and ``key2=value2`` to ``httpbin.org/get``, you would use the
following code::

    >>> payload = {'key1': 'value1', 'key2': 'value2'}
    >>> r = yield from aiohttp.request('get',
    ...                                'http://httpbin.org/get',
    ...                                params=payload)

You can see that the URL has been correctly encoded by printing the URL::

    >>> print(r.url)
    http://httpbin.org/get?key2=value2&key1=value1

It is also possible to pass a list of 2 item tuples as parameters, in
that case you can specifiy multiple values for each key::

    >>> payload = [('key', 'value1'), ('key': 'value2')]
    >>> r = yield from aiohttp.request('get',
    ...                                'http://httpbin.org/get',
    ...                                params=payload)
    >>> print(r.url)
    http://httpbin.org/get?key=value2&key=value1


Response Content
----------------

We can read the content of the server's response. Consider the GitHub timeline
again::

    >>> import aiohttp
    >>> r = yield from aiohttp.request(
    ...     'get', 'https://github.com/timeline.json')
    >>> yield from r.text()
    '[{"repository":{"open_issues":0,"url":"https://github.com/...

aiohttp will automatically decode the content from the server. You can
specify custom encoding for the ``text()`` method.

.. code::

    >>> yield from r.text(encoding='windows-1251')


Binary Response Content
-----------------------

You can also access the response body as bytes, for non-text requests::

    >>> yield from r.read()
    b'[{"repository":{"open_issues":0,"url":"https://github.com/...

The ``gzip`` and ``deflate`` transfer-encodings are automatically
decoded for you.


JSON Response Content
---------------------

There's also a builtin JSON decoder, in case you're dealing with JSON data::

    >>> import aiohttp
    >>> r = yield from aiohttp.request(
    ...     'get', 'https://github.com/timeline.json')
    >>> yield from r.json()
    [{'repository': {'open_issues': 0, 'url': 'https://github.com/...

In case that JSON decoding fails, ``r.json()`` will raise an exception. It
is possible to specify custom encoding and decoder functions for the
``json()`` call.


Streaming Response Content
--------------------------

While methods ``read()``, ``json()`` and ``text()`` are very convenient
you should use them carefully. All this methods loads the whole response in memory.
For example if you want to download several gigabyte sized files, this methods
will load all the data in memory. Instead you can use the ``ClientResponse.content``
attribute. It is an instance of the ``aiohttp.StreamReader`` class. The ``gzip``
and ``deflate`` transfer-encodings are automatically decoded for you.

.. code::

    >>> r = yield from aiohttp.request(
    ...     'get', 'https://github.com/timeline.json')
    >>> r.content
    <aiohttp.streams.StreamReader object at 0x...>
    >>> yield from r.content.read(10)
    '\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03'

In general, however, you should use a pattern like this to save what is being
streamed to a file::

    >>> with open(filename, 'wb') as fd:
    ...     while True:
    ...         chunk = yield from r.content.read(chunk_size)
    ...         if not chunk:
    ...             break
    ...         fd.write(chunk)

It is not possible to use ``read()``, ``json()`` and ``text()`` after reading the file
with ``chunk_size``.


Custom Headers
--------------

If you need to add HTTP headers to a request, pass them in a ``dict`` to the
``headers`` parameter.

For example, if you want to specify the content-type for the previous example::

    >>> import json
    >>> url = 'https://api.github.com/some/endpoint'
    >>> payload = {'some': 'data'}
    >>> headers = {'content-type': 'application/json'}

    >>> r = yield from aiohttp.request('post',
    ...                                url,
    ...                                data=json.dumps(payload),
    ...                                headers=headers)


Custom Cookies
--------------

To send your own cookies to the server, you can use the ``cookies``
parameter::

    >>> url = 'http://httpbin.org/cookies'
    >>> cookies = dict(cookies_are='working')

    >>> r = yield from aiohttp.request('get', url, cookies=cookies)
    >>> yield from r.text()
    '{"cookies": {"cookies_are": "working"}}'


More complicated POST requests
------------------------------

Typically, you want to send some form-encoded data — much like an HTML form.
To do this, simply pass a dictionary to the ``data`` argument. Your
dictionary of data will automatically be form-encoded when the request is made::

    >>> payload = {'key1': 'value1', 'key2': 'value2'}
    >>> r = yield from aiohttp.request('post',
    ...                                'http://httpbin.org/post',
    ...                                data=payload)
    >>> yield from r.text()
    {
      ...
      "form": {
        "key2": "value2",
        "key1": "value1"
      },
      ...
    }

If you want to send data that is not form-encoded you can do it by passing a ``string``
instead of a ``dict``. This data will be posted directly.

For example, the GitHub API v3 accepts JSON-Encoded POST/PATCH data::

    >>> import json
    >>> url = 'https://api.github.com/some/endpoint'
    >>> payload = {'some': 'data'}

    >>> r = yield from aiohttp.request(
    ...     'post', url, data=json.dumps(payload))


POST a Multipart-Encoded File
-----------------------------

To upload Multipart-encoded files::

    >>> url = 'http://httpbin.org/post'
    >>> files = {'file': open('report.xls', 'rb')}

    >>> yield from aiohttp.request('post', url, data=files)

You can set the filename, content_type explicitly::

    >>> url = 'http://httpbin.org/post'
    >>> data = FormData()
    >>> data.add_field('file',
    ...                open('report.xls', 'rb'),
    ...                filename='report.xls',
    ...                content_type='application/vnd.ms-excel')

    >>> yield from aiohttp.request('post', url, data=data)

If you pass a file object as data parameter, aiohttp will stream it to the server
automatically. Check :class:`aiohttp.stream.StreamReader` for supported format
information.

.. seealso:: :ref:`aiohttp-multipart`


Streaming uploads
-----------------

aiohttp support multiple types of streaming uploads, which allows you to
send large files without reading them into memory.

As a simple case, simply provide a file-like object for your body::

    >>> with open('massive-body', 'rb') as f:
    ...   yield from aiohttp.request(
    ...       'post', 'http://some.url/streamed', data=f)


Or you can provide an ``asyncio`` coroutine that yields bytes objects::

   >>> @asyncio.coroutine
   ... def my_coroutine():
   ...    chunk = yield from read_some_data_from_somewhere()
   ...    if not chunk:
   ...       return
   ...    yield chunk

.. note::
   It is not a standard ``asyncio`` coroutine as it yields values so it
   can not be used like ``yield from my_coroutine()``.
   ``aiohttp`` internally handles such coroutines.

Also it is possible to use a ``StreamReader`` object. Lets say we want to upload
a file from another request and calculate the file sha1 hash::

   >>> def feed_stream(resp, stream):
   ...    h = hashlib.sha1()
   ...
   ...    with True:
   ...       chunk = yield from resp.content.readany()
   ...       if not chunk:
   ...          break
   ...       h.update(chunk)
   ...       s.feed_data(chunk)
   ...
   ...    return h.hexdigest()

   >>> resp = aiohttp.request('get', 'http://httpbin.org/post')
   >>> stream = StreamReader()
   >>> asyncio.async(aiohttp.request(
   ...     'post', 'http://httpbin.org/post', data=stream))

   >>> file_hash = yield from feed_stream(resp, stream)


Because the response content attribute is a StreamReader, you can chain get and
post requests together::

   >>> r = yield from aiohttp.request('get', 'http://python.org')
   >>> yield from aiohttp.request('post',
   ...                            'http://httpbin.org/post',
   ...                            data=r.content)


.. _aiohttp-client-session:

Keep-Alive, connection pooling and cookie sharing
-------------------------------------------------

To share cookies between multiple requests you can create an 
``aiohttp.ClientSession`` object:

    >>> session = aiohttp.ClientSession()
    >>> yield from session.get(
    ...     'http://httpbin.org/cookies/set/my_cookie/my_value')
    >>> r = yield from session.get('http://httpbin.org/cookies')
    >>> json = yield from r.json()
    >>> json['cookies']['my_cookie']
    'my_value'

You also can set default headers for all session requests:

    >>> session = aiohttp.ClientSession(
    ...     headers={"Authorization": "Basic bG9naW46cGFzcw=="})
    >>> r = yield from s.get("http://httpbin.org/headers")
    >>> json = yield from r.json()
    >>> json['headers']['Authorization']
    'Basic bG9naW46cGFzcw=='

By default aiohttp does not use connection pooling. In other words multiple
calls to ``aiohttp.request`` will start a new connection to host each.
``aiohttp.ClientSession`` object will do connection pooling for you.


Connectors
----------

To tweek or change *transport* layer of requests you can pass a custom
**Connector** to ``aiohttp.request``. For example:

    >>> conn = aiohttp.TCPConnector()
    >>> r = yield from aiohttp.request(
    ...     'get', 'http://python.org', connector=conn)


SSL control for tcp sockets
---------------------------

:class:`aiohttp.connector.TCPConnector` constructor accepts mutually
exclusive *verify_ssl* and *ssl_context* params.

By default it uses strict checks for HTTPS protocol. Certification
checks can be relaxed by passing ``verify_ssl=False``::

  >>> conn = aiohttp.TCPConnector(verify_ssl=False)
  >>> r = yield from aiohttp.request(
  ...     'get', 'https://example.com', connector=conn)


If you need to setup custom ssl parameters (use own certification
files for example) you can create a :class:`ssl.SSLContext` instance and
pass it into the connector::

  >>> sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
  >>> sslcontext.verify_mode = ssl.CERT_REQUIRED
  >>> sslcontext.load_verify_locations("/etc/ssl/certs/ca-bundle.crt")
  >>> conn = aiohttp.TCPConnector(ssl_context=sslcontext)
  >>> r = yield from aiohttp.request(
  ...     'get', 'https://example.com', connector=conn)


Unix domain sockets
-------------------

If your http server uses unix domain sockets you can use
:class:`aiohttp.connector.UnixConnector`::

  >>> conn = aiohttp.UnixConnector(path='/path/to/socket')
  >>> r = yield from aiohttp.request(
  ...     'get', 'http://python.org', connector=conn)


Proxy support
-------------

aiohttp supports proxy. You have to use
:class:`aiohttp.connector.ProxyConnector`::

   >>> conn = aiohttp.ProxyConnector(proxy="http://some.proxy.com")
   >>> r = yield from aiohttp.request('get',
   ...                                'http://python.org',
   ...                                connector=conn)

``ProxyConnector`` also supports proxy authorization::

   >>> conn = aiohttp.ProxyConnector(
   ...   proxy="http://some.proxy.com",
   ...   proxy_auth=aiohttp.BasicAuth('user', 'pass'))
   >>> r = yield from aiohttp.request('get',
   ...                                'http://python.org',
   ...                                connector=conn)

Auth credentials can be passed in proxy URL::

   >>> conn = aiohttp.ProxyConnector(
   ...     proxy="http://user:pass@some.proxy.com")
   >>> r = yield from aiohttp.request('get',
   ...                                'http://python.org',
   ...                                 connector=conn)


Response Status Codes
---------------------

We can check the response status code::

   >>> r = aiohttp.request('get', 'http://httpbin.org/get')
   >>> r.status
   200


Response Headers
----------------

We can view the server's response headers using a Python dictionary::

    >>> r.headers
    {'ACCESS-CONTROL-ALLOW-ORIGIN': '*',
     'CONTENT-TYPE': 'application/json',
     'DATE': 'Tue, 15 Jul 2014 16:49:51 GMT',
     'SERVER': 'gunicorn/18.0',
     'CONTENT-LENGTH': '331',
     'CONNECTION': 'keep-alive'}

The dictionary is special, though: it's made just for HTTP headers. According to
`RFC 7230 <http://tools.ietf.org/html/rfc7230#section-3.2>`_, HTTP Header names
are case-insensitive.

So, we can access the headers using any capitalization we want::

    >>> r.headers['Content-Type']
    'application/json'

    >>> r.headers.get('content-type')
    'application/json'


Response Cookies
----------------

If a response contains some Cookies, you can quickly access them::

    >>> url = 'http://example.com/some/cookie/setting/url'
    >>> r = yield from aiohttp.request('get', url)

    >>> r.cookies['example_cookie_name']
    'example_cookie_value'

.. note::
   Response cookies contain only values, that were in ``Set-Cookie`` headers 
   of the **last** request in redirection chain. To gather cookies between all
   redirection requests you can use :ref:`aiohttp.ClientSession 
   <aiohttp-client-session>` object.


Timeouts
--------

You should use ``asyncio.wait_for()`` method if you want to limit
time to wait for a response from a server::

    >>> yield from asyncio.wait_for(
    ...     aiohttp.request('get', 'http://github.com'),
    ...     0.001)
    Traceback (most recent call last)\:
      File "<stdin>", line 1, in <module>
    asyncio.TimeoutError()


.. warning::

    ``timeout`` is not a time limit on the entire response download;
    rather, an exception is raised if the server has not issued a
    response for ``timeout`` seconds (more precisely, if no bytes have been
    received on the underlying socket for ``timeout`` seconds).
