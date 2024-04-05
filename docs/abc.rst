.. _aiohttp-abc:

Abstract Base Classes
=====================

.. module:: aiohttp.abc

Abstract routing
----------------

aiohttp has abstract classes for managing web interfaces.

The most part of :mod:`aiohttp.web` is not intended to be inherited
but few of them are.

aiohttp.web is built on top of few concepts: *application*, *router*,
*request* and *response*.

*router* is a *pluggable* part: a library user may build a *router*
from scratch, all other parts should work with new router seamlessly.

:class:`aiohttp.abc.AbstractRouter` has the only mandatory method:
:meth:`aiohttp.abc.AbstractRouter.resolve` coroutine. It must return an
:class:`aiohttp.abc.AbstractMatchInfo` instance.

If the requested URL handler is found
:meth:`aiohttp.abc.AbstractMatchInfo.handler` is a :term:`web-handler` for
requested URL and :attr:`aiohttp.abc.AbstractMatchInfo.http_exception` is ``None``.

Otherwise :attr:`aiohttp.abc.AbstractMatchInfo.http_exception` is an instance of
:exc:`~aiohttp.web.HTTPException` like *404: NotFound* or *405: Method
Not Allowed*. :meth:`aiohttp.abc.AbstractMatchInfo.handler` raises
:attr:`~aiohttp.abc.AbstractMatchInfo.http_exception` on call.


.. class:: AbstractRouter

   Abstract router, :class:`aiohttp.web.Application` accepts it as
   *router* parameter and returns as
   :attr:`aiohttp.web.Application.router`.

   .. method:: resolve(request)
      :async:

      Performs URL resolving. It's an abstract method, should be
      overridden in *router* implementation.

      :param request: :class:`aiohttp.web.Request` instance for
                      resolving, the request has
                      :attr:`aiohttp.web.Request.match_info` equals to
                      ``None`` at resolving stage.

      :return: :class:`aiohttp.abc.AbstractMatchInfo` instance.


.. class:: AbstractMatchInfo

   Abstract *match info*, returned by :meth:`aiohttp.abc.AbstractRouter.resolve` call.

   .. attribute:: http_exception

      :exc:`aiohttp.web.HTTPException` if no match was found, ``None``
      otherwise.

   .. method:: handler(request)
      :async:

      Abstract method performing :term:`web-handler` processing.

      :param request: :class:`aiohttp.web.Request` instance for
                      resolving, the request has
                      :attr:`aiohttp.web.Request.match_info` equals to
                      ``None`` at resolving stage.
      :return: :class:`aiohttp.web.StreamResponse` or descendants.

      :raise: :class:`aiohttp.web.HTTPException` on error

   .. method:: expect_handler(request)
      :async:

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

   The cookie jar instance is available as :attr:`aiohttp.ClientSession.cookie_jar`.

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

   .. method:: clear(predicate=None)

      Removes all cookies from the jar if the predicate is ``None``. Otherwise remove only those :class:`~http.cookies.Morsel` that ``predicate(morsel)`` returns ``True``.

      :param predicate: callable that gets :class:`~http.cookies.Morsel` as a parameter and returns ``True`` if this :class:`~http.cookies.Morsel` must be deleted from the jar.

          .. versionadded:: 3.8

   .. method:: clear_domain(domain)

      Remove all cookies from the jar that belongs to the specified domain or its subdomains.

      :param str domain: domain for which cookies must be deleted from the jar.

      .. versionadded:: 3.8

Abstract Access Logger
-------------------------------

.. class:: AbstractAccessLogger

   An abstract class, base for all :class:`aiohttp.web.RequestHandler`
   ``access_logger`` implementations

   Method ``log`` should be overridden.

   .. method:: log(request, response, time)

      :param request: :class:`aiohttp.web.Request` object.

      :param response: :class:`aiohttp.web.Response` object.

      :param float time: Time taken to serve the request.


Abstract Resolver
-------------------------------

.. class:: AbstractResolver

   An abstract class, base for all resolver implementations.

   Method ``resolve`` should be overridden.

   .. method:: resolve(host, port, family)

      Resolve host name to IP address.

      :param str host: host name to resolve.

      :param int port: port number.

      :param int family: socket family.

      :return: list of :class:`aiohttp.abc.ResolveResult` instances.

   .. method:: close()

      Release resolver.

.. class:: ResolveResult

   Result of host name resolution.

   .. attribute:: hostname

      The host name that was provided.

   .. attribute:: host

      The IP address that was resolved.

   .. attribute:: port

      The port that was resolved.

   .. attribute:: family

      The address family that was resolved.

   .. attribute:: proto

      The protocol that was resolved.

   .. attribute:: flags

      The flags that were resolved.
