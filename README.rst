http client/server for asyncio
==============================

.. image:: https://secure.travis-ci.org/KeepSafe/aiohttp.png
  :target:  https://secure.travis-ci.org/KeepSafe/aiohttp

.. image:: https://coveralls.io/repos/KeepSafe/aiohttp/badge.png?branch=master
  :target: https://coveralls.io/r/KeepSafe/aiohttp?branch=master


Requirements
------------

- Python >= 3.3
- asyncio https://pypi.python.org/pypi/asyncio/0.4.1


License
-------

``aiohttp`` is offered under the BSD license.

Getting started
---------------

To retrieve something from the web::

  import aiohttp

  def get_body(url):
      response = yield from aiohttp.request('GET', url)
      return (yield from response.read_and_close())

You can use the get command like this anywhere in your ``asyncio``
powered program::

  response = yield from aiohttp.request('GET', 'http://python.org')
  body = yield from response.read_and_close()
  print(body)

The signature of request is the following::

  request(method, url, *,
          params=None,
          data=None,
          headers=None,
          cookies=None,
          files=None,
          auth=None,
          allow_redirects=True,
          max_redirects=10,
          encoding='utf-8',
          version=(1, 1),
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
- ``data``: (optional) Dictionary, bytes, or file-like object to
  send in the body of the request
- ``headers``: (optional) Dictionary of HTTP Headers to send with the request
- ``cookies``: (optional) Dict object to send with the request
- ``files``: (optional) Dictionary of 'name': file-like-objects
  for multipart encoding upload
- ``auth``: (optional) Auth tuple to enable Basic HTTP Auth
- ``allow_redirects``: (optional) Boolean. Set to True if POST/PUT/DELETE
  redirect following is allowed.
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

   yield from asyncio.wait_for(request('GET', url), 10))

Gunicorn worker
---------------

Paster configuration example::

   [server:main]
   use = egg:gunicorn#main
   host = 0.0.0.0
   port = 8080
   worker_class = aiohttp.worker.AsyncGunicornWorker
