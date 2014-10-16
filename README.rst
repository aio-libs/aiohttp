http client/server for asyncio
==============================

.. image:: https://raw.github.com/KeepSafe/aiohttp/master/docs/aiohttp-icon.png
  :height: 64px
  :width: 64px
  :alt: aiohttp logo

.. image:: https://secure.travis-ci.org/KeepSafe/aiohttp.png
  :target:  https://secure.travis-ci.org/KeepSafe/aiohttp
  :align: right


Requirements
------------

- Python >= 3.3
- asyncio https://pypi.python.org/pypi/asyncio


License
-------

``aiohttp`` is offered under the BSD license.


Documentation
-------------

http://aiohttp.readthedocs.org/


Getting started
---------------

To retrieve something from the web::

  import aiohttp

  def get_body(url):
      response = yield from aiohttp.request('GET', url)
      return (yield from response.read())

You can use the get command like this anywhere in your ``asyncio``
powered program::

  response = yield from aiohttp.request('GET', 'http://python.org')
  body = yield from response.read()
  print(body)

The signature of request is the following::

  request(method, url, *,
          params=None,
          data=None,
          headers=None,
          cookies=None,
          auth=None,
          allow_redirects=True,
          max_redirects=10,
          encoding='utf-8',
          version=aiohttp.HttpVersion11,
          compress=None,
          chunked=None,
          expect100=False,
          connector=None,
          read_until_eof=True,
          request_class=None,
          response_class=None,
          loop=None
  )

It constructs and sends a request. It returns response object. Parameters are explained as follow:

- ``method``: HTTP method
- ``url``: Request url
- ``params``: (optional) Dictionary or bytes to be sent in the query string
  of the new request
- ``data``: (optional) Dictionary, bytes, StreamReader or file-like object to
  send in the body of the request
- ``headers``: (optional) Dictionary of HTTP Headers to send with the request
- ``cookies``: (optional) Dict object to send with the request
- ``auth``: (optional) `BasicAuth` tuple to enable Basic HTTP Basic Auth
- ``allow_redirects``: (optional) Boolean. Set to True if POST/PUT/DELETE
  redirect following is allowed.
- ``version``: Request http version.
- ``compress``: Boolean. Set to True if request has to be compressed
  with deflate encoding.
- ``chunked``: Boolean or Integer. Set to chunk size for chunked
  transfer encoding.
- ``expect100``: Boolean. Expect 100-continue response from server.
- ``connector``: ``aiohttp.connector.BaseConnector`` instance to support
  connection pooling and session cookies.
- ``read_until_eof``: Read response until eof if response
  does not have Content-Length header.
- ``request_class``: Custom Request class implementation.
- ``response_class``: Custom Response class implementation.
- ``loop``: Optional event loop.

If you want to use timeouts for aiohttp client side please use standard
asyncio approach::

   yield from asyncio.wait_for(request('GET', url), 10)


Gunicorn worker
---------------

Since version 0.19.0 gunicorn has native support for aiohttp.

Paster configuration example::

   [server:main]
   use = egg:gunicorn#main
   host = 0.0.0.0
   port = 8080
   worker_class = aiohttp.worker.AsyncGunicornWorker
