.. _web:

.. highlight:: python

High-level HTTP Server
======================

.. module:: aiohttp.web

.. versionadded:: 0.10

Run a simple web server
-----------------------

For implementing web server at first create :ref:`request handler<web-handler>`.

Handler is a :ref:`coroutine<coroutine>` or regular function that
accepts only *request* parameter of type :class:`Request`
and returns :class:`Response` instance::

   import asyncio
   from aiohttp import web

   @asyncio.coroutine
   def hello(request):
       return web.Response(request, b"Hello, world")

Next you have to create *application* and register *handler* in
application's router pointing *HTTP method*, *path* and *handler*::

   app = web.Application()
   app.router.add_route('GET', '/', hello)

After that create server and run *asyncio loop* as usual::

   loop = asyncio.get_event_loop()
   f = loop.create_server(app.make_handler, '0.0.0.0', '8080')
   srv = loop.run_until_complete(f)
   print('serving on', srv.sockets[0].getsockname())
   try:
       loop.run_forever()
   except KeyboardInterrupt:
       pass

That's it.

.. _web-handler:

Handler
-------

Handler is an any *callable* that accepts single :class:`Request`
argument and returns :class:`StreamResponse` derived
(e.g. :class:`Response`) instance.

Handler **can** be a :ref:`coroutine<coroutine>`, :mod:`aiohttp.web` will
**unyield** returned result by applying ``yield from`` to handler.

Handlers can be first-class functions like::

   @asyncio.coroutine
   def hello(request):
       return web.Response(request, b"Hello, world")

   app.router.add_route('GET', '/', hello)

Sometimes you would like to group logically coupled handlers into python class.

:mod:`aiohttp.web` doesn't dictate any implementation details on that
class: library user is responsible for instantiating and
connecting routes::

   class Handler:

       def __init__(self):
           pass

       def handle_intro(self, request):
           return web.Response(request, b"Hello, world")

       @asyncio.coroutine
       def handle_greeting(self, request):
           name = request.match_info.get('name')
           txt = "Hello, {}".format(name)
           return web.Response(request, txt.encode('utf-8')

   handler = Handler()
   app.router.add_route('GET', '/intro', handler.handle_intro)
   app.router.add_route('GET', '/greet/{name}', handler.handle_greeting)


.. _web-request:


Request
-------

Request object contains all information about incoming HTTP request.

Every :ref:`handler<web-handler>` accepts request instance as first
positional parameter.

.. note::

   You should never create :class:`Request` instance by hands --
   :mod:`aiohttp.web` does it for you.

.. class:: Request

Common properties
^^^^^^^^^^^^^^^^^

   .. attribute:: method

      *HTTP method*, read only property.

      The value is upper-cased :class:`str` like ``"GET"``,
      ``"POST"``, ``"PUT"`` etc.

   .. attribute:: version

      *HTTP version* of request, read only property.

      Returns :class:`aiohttp.protocol.HttpVersion` instance.

   .. attribute:: host

      *HOST* header of request, read only property.

      Returns :class:`str` or ``None`` if HTTP request has no *HOST* header.

   .. attribute:: path_qs

      The URL including PATH_INFO and the query string. e.g, ``/app/blog?id=10``

      Read only :class:`str` property.

   .. attribute:: path

      The URL including *PATH INFO* without the host or scheme. e.g.,
      ``/app/blog``

      Read only :class:`str` property.

   .. attribute:: query_string

      The query string in the URL, e.g., ``id=10``

      Read only :class:`str` property.

   .. attribute:: GET

      A multidict with all the variables in the query string.

      Read only :class:`~aiohttp.multidict.MultiDict` lazy property.

   .. attribute:: headers

      A case-insensitive multidict with all headers.

      Read only :class:`~aiohttp.multidict.CaseInsensitiveMultiDict`
      lazy property.

   .. attribute:: keep_alive

      ``True`` if keep-alive connection enabled by HTTP client and
      protocol version supports it, otherwise ``False``.

      Read only :class:`bool` property.

   .. attribute:: match_info

      Read only property with :class:`~aiohttp.abc.AbstractMatchInfo`
      instance for result of route resolving.

      .. note::

         Exact type of property depends on used router.  If
         ``app.router`` is :class:`UrlDispatcher` the property contains
         :class:`UrlMappingMatchInfo` instance.

   .. attribute:: app

      An :class:`Application` instance used to call :ref:`request handler
      <web-handler>`, read only property.

   .. attribute:: cookies

      A multidict of all request's cookies.

      Read only :class:`~aiohttp.multidict.MultiDict` lazy property.

   .. attribute:: payload

      A :class:`~aiohttp.streams.FlowControlStreamReader` instance,
      input stream for reading request's *BODY*.

      Read only property.

Shortcuts for request headers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   .. attribute:: content_type

      Read only property with *content* part of *Content-Type* header.

      Returns :class:`str` like ``'text/html'``

      .. note::

         Returns value is ``'application/octet-stream'`` if no
         Content-Type header present in HTTP headers according to
         :rfc:`2616`

   .. attribute:: charset

      Read only property that specifies *encoding* for request BODY.

      The value is parsed from *Content-Type* HTTP header.

      Returns :class:`str` like ``'utf-8'`` or ``None`` if
      *Content-Type* has no charset information.

   .. attribute:: content_length

      Read only property that returns length of request BODY.

      The value is parsed from *Content-Length* HTTP header.

      Returns :class:`int` or ``None`` if *Content-Length* is absent.

Request's methods
^^^^^^^^^^^^^^^^^

   .. method:: read()

      Read request body, returns :class:`bytes` object with body content.

      The method is a :ref:`coroutine <coroutine>`.

      .. warning::

         The method doesn't store read data internally, subsequent
         :meth:`~Request.read` call will return empty bytes ``b''``.

   .. method:: text()

      Read request body, decode it using :attr:`charset` encoding or
      ``UTF-8`` if no encoding was specified in *MIME-type*.

      Returns :class:`str` with body content.

      The method is a :ref:`coroutine <coroutine>`.

      .. warning::

         The method doesn't store read data internally, subsequent
         :meth:`~Request.text` call will return empty string ``''``.

   .. method:: json(*, loader=json.loads)

      Read request body decoded as *json*.

      The method is just a boilerplate :ref:`coroutine <coroutine>`
      implemented as::

         @asyncio.coroutine
         def json(self, *, loader=json.loads):
             body = yield from self.text()
             return loader(body)

      :param callable loader: any callable that accepts :class:`str`
                              and returns :class:`dict` with parsed
                              JSON (:func:`json.loads` by default).

      .. warning::

         The method doesn't store read data internally, subsequent
         :meth:`~Request.json` call will raise an exception.

   .. method:: POST()

      A :ref:`coroutine <coroutine>` that reads POST parameters from
      request body.

      Returns :class:`~aiohttp.multidict.MultiDict` instance filled
      with parsed data.

      If :attr:`method` is not *POST*, *PUT* or *PATCH* or
      :attr:`content_type` is not empty or
      *application/x-www-form-urlencoded* or *multipart/form-data*
      returns empty multidict.

      .. warning::

         The method **does** store read data internally, subsequent
         :meth:`~Request.POST` call will return the same value.

   .. method:: release()

      Release request.

      Eat unread part of HTTP BODY if present.

      The method is a :ref:`coroutine <coroutine>`.

      .. note::

          User code may never call :meth:`~Request.release`, all
          required work will be processed by :mod:`aiohttp.web`
          internal machinery.


.. _web-response:


Response
--------

For now :mod:`aiohttp.web` has two classes for *HTTP response*:
:class:`StreamResponse` and :class:`Response`.

Usually you need to use the second one. :class:`StreamResponse`
intended for streaming data, :class:`Response` contains *HTTP BODY* as
attribute and sends own content as single piece with correct
*Content-Length HTTP header*.

For sake of design decisions :class:`Response` is derived from
:class:`StreamResponse` parent class.

The response supports *keep-alive* handling out-of-the-box if
*request* supports it.

You can disable *keep-alive* by :meth:`~StreamResponse.force_close` though.

The common case for sending answer from :ref:`web
handler<web-handler>` is returning :class:`Response` instance::

   def handler(request):
       return Response(request, "All right!")


StreamResponse
^^^^^^^^^^^^^^

.. class:: StreamResponse(request)

   The base class for *HTTP response* handling.

   Contains methods for setting *HTTP response headers*, *cookies*,
   *response status code*, writing *HTTP response BODY* and so on.

   The most important thing you should to know about *response* --- it
   is *Finite State Machine*.

   That means you can do any manipulations on *headers*,
   *cookies* and *status code* only before :meth:`send_headers`
   called.

   Once you call :meth:`send_headers` or :meth:`write` any change of
   *HTTP header* part will raise :exc:`RuntimeError` exception.

   Any :meth:`write` call after :meth:`write_eof` is forbidden also.

   :param aiohttp.web.Request request: HTTP request object on that the
                                       response answers.

   .. attribute:: request

      Read-only property for :class:`Request` object used for creating
      the response.

   .. attribute:: status

      Read-write property for *HTTP response status code*, :class:`int`.

      ``200`` (OK) by default.

   .. attribute:: keep_alive

      Read-only property, copy of :attr:`Request.keep_alive` by default.

      Can be switched to ``False`` by :meth:`force_close` call.

   .. method:: force_close

      Disable :attr:`keep_alive` for connection. There are no ways to
      enable it back.

   .. attribute:: headers

      :class:`~aiohttp.multidict.CaseInsensitiveMultiDict` instance
      for *outgoing* *HTTP headers*.

   .. attribute:: cookies

      An instance of :class:`http.cookies.SimpleCookie` for *outgoing* cookies.

      .. warning::

         Direct setting up *Set-Cookie* header may be overwritten by
         explicit calls to cookie manipulation.

         We are encourage using of :attr:`cookies` and
         :meth:`set_cookie`, :meth:`del_cookie` for cookie
         manipulations.

   .. method:: set_cookie(name, value, *, expires=None, \
                   domain=None, max_age=None, path=None, \
                   secure=None, httponly=None, version=None)

      Convenient way for setting :attr:`cookies`, allows to point
      additional cookie properties like *max_age* in single call.

      :param str name: cookie name

      :param str value: cookie value (will be converted to
                        :class:`str` if value has another type).

      :param expries: expiration date (optional)

      :param str domain: cookie domain (optional)

      :param int max_age: defines the lifetime of the cookie, in
                          seconds.  The delta-seconds value is a
                          decimal non- negative integer.  After
                          delta-seconds seconds elapse, the client
                          should discard the cookie.  A value of zero
                          means the cookie should be discarded
                          immediately.  (optional)

      :param str path: specifies the subset of URLs to
                       which this cookie applies. (optional)

      :param bool secure: attribute (with no value) directs
                          the user agent to use only (unspecified)
                          secure means to contact the origin server
                          whenever it sends back this cookie.
                          The user agent (possibly under the user's
                          control) may determine what level of
                          security it considers appropriate for
                          "secure" cookies.  The *secure* should be
                          considered security advice from the server
                          to the user agent, indicating that it is in
                          the session's interest to protect the cookie
                          contents. (optional)

      :param bool httponly: ``True`` if the cookie HTTP only (optional)

      :param int version: a decimal integer, identifies to which
                          version of the state management
                          specification the cookie
                          conforms. (Optional, *version*=1 by default)

   .. method:: del_cookie(name, *, domain=None, path=None)

      Deletes cookie.

      :param str name: cookie name

      :param str domain: optional cookie domain

      :param str path: optional cookie path

      .. warning::

         The method is a bit inconsistent.

         It allows to delete cookie not exists on class creation time.

         [TBD]: explain it.

   .. attribute:: content_length

      *Content-Length* for outgoing response.

   .. attribute:: content_type

      *Content* part of *Content-Type* for outgoing response.

   .. attribute:: charset

      *Charset* aka *encoding* part of *Content-Type* for outgoing response.

   .. method:: send_headers()

      Send *HTTP header*. You should not change any header data after
      calling the method.

   .. method:: write(data)

      Send byte-ish data as part of *response BODY*.

      Calls :meth:`send_headers` if not been called.

      Raises :exc:`TypeError` if data is not :class:`bytes`,
      :class:`bytearray` or :class:`memoryview` instance.

      Raises :exc:`RuntimeError` if :meth:`write_eof` has been called.

   .. method:: write_eof()

      A :ref:`coroutine<coroutine>` *may* be called as mark of finish
      *HTTP response* processing.

      *Internal machinery* will call the method at the end of request
      processing if needed.

      After :meth:`write_eof` call any manipulations with *response*
      object are forbidden.

Response
^^^^^^^^

.. class:: Response(request, body=None, *, status=200, headers=None)

   The most usable response class.

   Accepts *body* argument for setting *HTTP response BODY*.

   Actual :attr:`body` sending is done in overridden
   :meth:`~StreamResponse.write_eof`.

   :param Request request: *HTTP request* object used for creation the response.

   :param bytes body: response's BODY

   :param int status: HTTP status code, 200 OK by default.

   :param collections.abc.Mapping headers: HTTP headers that should be added to
                           response's ones.

   .. attribute:: body

      Read-write attribute for storing response's content aka BODY,
      :class:`bytes`.

      Setting :attr:`body` also recalculates :attr:`content_length` value.

      Resetting :attr:`body` (assigning ``None``) set
      :attr:`content_length` no ``None`` also, dropping
      *Content-Length* HTTP header.

Content Type
------------

Content-Type header is case-insensitive by :rfc:`2045`, BTW.
