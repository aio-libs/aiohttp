.. _aiohttp-client-reference:

HTTP Client Reference
=====================

.. highlight:: python

.. module:: aiohttp.web


.. _aiohttp-web-request:


request function
----------------

.. py:function:: request(method, url, *, params=None, data=None, headers=None, cookies=None, files=None, auth=None, allow_redirects=True, max_redirects=10, encoding='utf-8', version=HttpVersion(major=1, minor=1), compress=None, chunked=None, expect100=False, connector=None, loop=None, read_until_eof=True, request_class=None, response_class=None, test=None)
   :module: aiohttp.client

   Performs an asyncronous http request. Returns a response object.

   The function is a :ref:`coroutine <coroutine>`.

   :param str method: HTTP method

   :param str url: Request URL

   :param params: Dictionary or bytes to be sent in the query
                  string of the new request (optional)

   :param data: Dictionary, bytes, or file-like object to
                send in the body of the request (optional)

   :param dict headers: Dictionary of HTTP Headers to send with
                        the request (optional)

   :param dict cookies: Cookies to send with the request (optional)

   :param aiohttp.helpers.BasicAuth auth: BasicAuth named tuple that represents
                                          HTTP Basic Auth (optional)

   :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                ``True`` by default (optional).

   :param aiohttp.protocol.HttpVersion version: Request http version (optional)

   :param bool compress: Set to ``True`` if request has to be compressed
                         with deflate encoding.
                         ``None`` by default (optional).

   :param chunked: Set to chunk size for chunked transfer encoding.
                   ``None`` by default (optional).

   :param bool expect100: Expect 100-continue response from server.
                          ``False`` by default (optional).

   :param aiohttp.connector.BaseConnector connector: BaseConnector sub-class
                                                     instance to support connection pooling.

   :param bool read_until_eof: Read response until eof if response
                               does not have Content-Length header.
                               ``True`` by default (optional).

   :param request_class: Custom Request class implementation (optional)

   :param response_class: Custom Response class implementation (optional)

   :param loop: :ref:`event loop<asyncio-event-loop>`
                used for processing HTTP requests.
                If param is ``None``, :func:`asyncio.get_event_loop`
                is used for getting default event loop, but we strongly
                recommend to use explicit loops everywhere.
                (optional)


Usage::

     >>> import aiohttp
     >>> resp = yield from aiohttp.request('GET', 'http://python.org/')
     >>> resp
     <ClientResponse(python.org/) [200]>
     >>> data = yield from resp.read()


Client Session
--------------

.. py:class:: ClientSession(*, connector=None, loop=None, request_class=None, response_class=None, cookies=None, headers=None, auth=None)
   :module: aiohttp.client

   The class for creating client sessions and making requests.

   :param aiohttp.connector.BaseConnector connector: BaseConnector sub-class
                                                     instance to support connection pooling.


   :param loop: :ref:`event loop<asyncio-event-loop>`
            used for processing HTTP requests.
            If param is ``None``, :func:`asyncio.get_event_loop`
            is used for getting default event loop, but we strongly
            recommend to use explicit loops everywhere.
            (optional)


   :param request_class: Custom Request class implementation (optional)

   :param response_class: Custom Response class implementation (optional)

   :param dict cookies: Cookies to send with the request (optional)

   :param dict headers: Dictionary of HTTP Headers to send with
                        the request (optional)

   :param aiohttp.helpers.BasicAuth auth: BasicAuth named tuple that represents
                                          HTTP Basic Auth (optional)


   .. py:method:: ClientSession.request(method, url, *, params=None, data=None, headers=None, auth=None, allow_redirects=True, max_redirects=10, encoding='utf-8', version=HttpVersion(major=1, minor=1), compress=None, chunked=None, expect100=False, read_until_eof=True)
      :module: aiohttp.client

      Performs an asyncronous http request. Returns a response object.

      The function is a :ref:`coroutine <coroutine>`.

      :param str method: HTTP method

      :param str url: Request URL

      :param params: Dictionary or bytes to be sent in the query
                     string of the new request (optional)

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

      :param dict headers: Dictionary of HTTP Headers to send with
                          the request (optional)

      :param aiohttp.helpers.BasicAuth auth: BasicAuth named tuple that represents
                                             HTTP Basic Auth (optional)

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).

      :param aiohttp.protocol.HttpVersion version: Request http version (optional)

      :param bool compress: Set to ``True`` if request has to be compressed
                            with deflate encoding.
                            ``None`` by default (optional).

      :param chunked: Set to chunk size for chunked transfer encoding.
                      ``None`` by default (optional).

      :param bool expect100: Expect 100-continue response from server.
                             ``False`` by default (optional).

      :param bool read_until_eof: Read response until eof if response
                                  does not have Content-Length header.
                                  ``True`` by default (optional).




   .. py:method:: ClientSession.get(url, *, allow_redirects=True, **kwargs)
      :module: aiohttp.client

      Perform a ``GET`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).


   .. py:method:: ClientSession.post(url, *, data=None, **kwargs)
      :module: aiohttp.client

      Perform a ``POST`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

   .. py:method:: ClientSession.put(url, *, data=None, **kwargs)
      :module: aiohttp.client

      Perform a ``PUT`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)

   .. py:method:: ClientSession.delete(url, **kwargs)
      :module: aiohttp.client

      Perform a ``DELETE`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

   .. py:method:: ClientSession.head(url, *, allow_redirects=False, **kwargs)
      :module: aiohttp.client

      Perform a ``HEAD`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``False`` by default (optional).


   .. py:method:: ClientSession.options(url, *, allow_redirects=True, **kwargs)
      :module: aiohttp.client

      Perform an ``OPTIONS`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

      :param bool allow_redirects: If set to ``False``, do not follow redirects.
                                   ``True`` by default (optional).


   .. py:method:: ClientSession.patch(url, *, data=None, **kwargs)
      :module: aiohttp.client

      Perform a ``PATCH`` request.
      In order to modify inner :func:`request<aiohttp.client.ClientSession.request>`
      parameters, provide `kwargs`.

      The function is a :ref:`coroutine <coroutine>`.

      :param str url: Request URL

      :param data: Dictionary, bytes, or file-like object to
                   send in the body of the request (optional)


