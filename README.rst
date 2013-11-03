http client/server for asyncio
==============================


.. image:: https://secure.travis-ci.org/fafhrd91/aiohttp.png
  :target:  https://secure.travis-ci.org/fafhrd91/aiohttp

.. image:: https://coveralls.io/repos/fafhrd91/aiohttp/badge.png?branch=master
  :target: https://coveralls.io/r/fafhrd91/aiohttp?branch=master


Requirements
------------

- Python >= 3.3
- asyncio https://pypi.python.org/pypi/asyncio/0.1.1


License
-------

``aiohttp`` is offered under the BSD license.

Getting started
---------------

To retrieve something from the web::

  from aiohttp import request

  def get_body(url):
      response = yield from request('GET', url)
      return response.read()

You can use the get command like this anywhere in your ``asyncio`` powered program::

  data = yield from get_body('http://python.org')

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
          timeout=None,
          compress=None,
          chunked=None,
          session=None,
          verify_ssl=True,
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
- ``timeout``: (optional) Float describing the timeout of the request
- ``allow_redirects``: (optional) Boolean. Set to True if POST/PUT/DELETE
  redirect following is allowed.
- ``compress``: Boolean. Set to True if request has to be compressed
  with deflate encoding.
- ``chunked``: Boolean or Integer. Set to chunk size for chunked
  transfer encoding.
- ``session``: ``aiohttp.Session`` instance to support connection pooling and
  session cookies.
- ``loop``: Optional event loop.

