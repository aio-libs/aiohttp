.. _aiohttp-abc:

Abstract Base Classes
=====================

.. module:: aiohttp

.. currentmodule:: aiohttp

Abstract routing
----------------

aiohttp has abstract classes for managing web interfaces.

The most part of :mod:`aiohttp.web` is not intended to be inherited
but few of them are.

aiohttp.web is built on top of few concepts: *application*, *router*,
*request* and *response*.

*router* is a *pluggable* part: a library user may build a *router*
from scratch, all other parts should work with new router seamlessly.

:class:`AbstractRouter` has the only mandatory method:
:meth:`AbstractRouter.resolve` coroutine. It must return an
:class:`AbstractMatchInfo` instance.

If the requested URL handler is found
:meth:`AbstractMatchInfo.handler` is a :term:`web-handler` for
requested URL and :attr:`AbstractMatchInfo.http_exception` is ``None``.

Otherwise :attr:`AbstractMatchInfo.http_exception` is an instance of
:exc:`~aiohttp.web.HTTPException` like *404: NotFound* or *405: Method
Not Allowed*. :meth:`AbstractMatchInfo.handler` raises
:attr:`~AbstractMatchInfo.http_exception` on call.


.. class:: AbstractRouter

   Abstract router, :class:`aiohttp.web.Application` accepts it as
   *router* parameter and returns as
   :attr:`aiohttp.web.Application.router`.

   .. coroutinemethod:: resolve(request)

      Performs URL resolving. It's an abstract method, should be
      overridden in *router* implementation.

      :param request: :class:`aiohttp.web.Request` instance for
                      resolving, the request has
                      :attr:`aiohttp.web.Request.match_info` equals to
                      ``None`` at resolving stage.

      :return: :class:`AbstractMatchInfo` instance.


.. class:: AbstractMatchInfo

   Abstract *match info*, returned by :meth:`AbstractRouter.resolve` call.

   .. attribute:: http_exception

      :exc:`aiohttp.web.HTTPException` if no match was found, ``None``
      otherwise.

   .. coroutinemethod:: handler(request)

      Abstract method performing :term:`web-handler` processing.

      :param request: :class:`aiohttp.web.Request` instance for
                      resolving, the request has
                      :attr:`aiohttp.web.Request.match_info` equals to
                      ``None`` at resolving stage.
      :return: :class:`aiohttp.web.StreamResponse` or descendants.

      :raise: :class:`aiohttp.web.HTTPException` on error

   .. coroutinemethod:: expect_handler(request)

      Abstract method for handling *100-continue* processing.


Abstract Class Based Views
--------------------------

For *class based view* support aiohttp has abstract
:class:`AbstractView` class which is *awaitable* (may be uses like
``await Cls()`` or ``yield from Cls()`` and has a *request* as an
attribute.

.. class:: AbstractView

   An abstract class, base for all *class based views* implementations.

   Methods ``__iter__`` and ``__await__`` should be overridden.

   .. attribute:: request

      :class:`aiohttp.web.Request` instance for performing the request.


Abstract Cookie Jar
-------------------

.. class:: AbstractCookieJar

   The cookie jar instance is available as :attr:`ClientSession.cookie_jar`.

   The jar contains :class:`~http.cookies.Morsel` items for storing
   internal cookie data.

   API provides a count of saved cookies::

       len(session.cookie_jar)

   These cookies may be iterated over::

       for cookie in session.cookie_jar:
           print(cookie.key)
           print(cookie["domain"])

   An abstract class for cookie storage. Implements
   :class:`collections.abc.Iterable` and
   :class:`collections.abc.Sized`.

   .. method:: update_cookies(cookies, response_url=None)

      Update cookies returned by server in ``Set-Cookie`` header.

      :param cookies: a :class:`collections.abc.Mapping`
         (e.g. :class:`dict`, :class:`~http.cookies.SimpleCookie`) or
         *iterable* of *pairs* with cookies returned by server's
         response.

      :param str response_url: URL of response, ``None`` for *shared
         cookies*.  Regular cookies are coupled with server's URL and
         are sent only to this server, shared ones are sent in every
         client request.

   .. method:: filter_cookies(request_url)

      Return jar's cookies acceptable for URL and available in
      ``Cookie`` header for sending client requests for given URL.

      :param str response_url: request's URL for which cookies are asked.

      :return: :class:`http.cookies.SimpleCookie` with filtered
         cookies for given URL.


.. disqus::
  :title: aiohttp abstact base classes
