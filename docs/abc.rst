.. _aiohttp-abc:

Abstract Base Classes
=====================

.. module:: aiohttp.abc

.. currentmodule:: aiohttp.abc

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
:meth:`AbstractRouter.resolve` coroutine. It should return an
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

   Abstract *match info*, returned by :meth:`AbstractRouter` call.

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

.. class:: AbstractCookieJar(*, loop=None)

   An abstract class for cookie storage.

   :param loop: an :ref:`event loop<asyncio-event-loop>` instance.

                If param is ``None`` :func:`asyncio.get_event_loop`
                used for getting default event loop, but we strongly
                recommend to use explicit loops everywhere.


   .. attribute:: cookies

      :class:`http.cookies.SimpleCookie` instance for storing cookies info.

   .. method:: update_cookies(cookies, response_url=None)

       Update cookies.

   .. method:: filter_cookies(request_url)

      Returns this jar's cookies filtered by their attributes.
