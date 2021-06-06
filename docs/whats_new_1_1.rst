=========================
What's new in aiohttp 1.1
=========================


YARL and URL encoding
======================

Since aiohttp 1.1 the library uses :term:`yarl` for URL processing.

New API
-------

:class:`yarl.URL` gives handy methods for URL operations etc.

Client API still accepts :class:`str` everywhere *url* is used,
e.g. ``session.get('http://example.com')`` works as well as
``session.get(yarl.URL('http://example.com'))``.

Internal API has been switched to :class:`yarl.URL`.
:class:`aiohttp.CookieJar` accepts :class:`~yarl.URL` instances only.

On server side has added :attr:`aiohttp.web.BaseRequest.url` and
:attr:`aiohttp.web.BaseRequest.rel_url` properties for representing relative and
absolute request's URL.

URL using is the recommended way, already existed properties for
retrieving URL parts are deprecated and will be eventually removed.

Redirection web exceptions accepts :class:`yarl.URL` as *location*
parameter. :class:`str` is still supported and will be supported forever.

Reverse URL processing for *router* has been changed.

The main API is ``aiohttp.web.Request.url_for``
which returns a :class:`yarl.URL` instance for named resource. It
does not support *query args* but adding *args* is trivial:
``request.url_for('named_resource', param='a').with_query(arg='val')``.

The method returns a *relative* URL, absolute URL may be constructed by
``request.url.join(request.url_for(...)`` call.


URL encoding
------------

YARL encodes all non-ASCII symbols on :class:`yarl.URL` creation.

Thus ``URL('https://www.python.org/путь')`` becomes
``'https://www.python.org/%D0%BF%D1%83%D1%82%D1%8C'``.

On filling route table it's possible to use both non-ASCII and percent
encoded paths::

   app.router.add_get('/путь', handler)

and::

   app.router.add_get('/%D0%BF%D1%83%D1%82%D1%8C', handler)

are the same. Internally ``'/путь'`` is converted into
percent-encoding representation.

Route matching also accepts both URL forms: raw and encoded by
converting the route pattern to *canonical* (encoded) form on route
registration.


Sub-Applications
================

Sub applications are designed for solving the problem of the big
monolithic code base.
Let's assume we have a project with own business logic and tools like
administration panel and debug toolbar.

Administration panel is a separate application by its own nature but all
toolbar URLs are served by prefix like ``/admin``.

Thus we'll create a totally separate application named ``admin`` and
connect it to main app with prefix::

   admin = web.Application()
   # setup admin routes, signals and middlewares

   app.add_subapp('/admin/', admin)

Middlewares and signals from ``app`` and ``admin`` are chained.

It means that if URL is ``'/admin/something'`` middlewares from
``app`` are applied first and ``admin.middlewares`` are the next in
the call chain.

The same is going for
:attr:`~aiohttp.web.Application.on_response_prepare` signal -- the
signal is delivered to both top level ``app`` and ``admin`` if
processing URL is routed to ``admin`` sub-application.

Common signals like :attr:`~aiohttp.web.Application.on_startup`,
:attr:`~aiohttp.web.Application.on_shutdown` and
:attr:`~aiohttp.web.Application.on_cleanup` are delivered to all
registered sub-applications. The passed parameter is sub-application
instance, not top-level application.


Third level sub-applications can be nested into second level ones --
there are no limitation for nesting level.


Url reversing
-------------

Url reversing for sub-applications should generate urls with proper prefix.

But for getting URL sub-application's router should be used::

   admin = web.Application()
   admin.add_get('/resource', handler, name='name')

   app.add_subapp('/admin/', admin)

   url = admin.router['name'].url_for()

The generated ``url`` from example will have a value
``URL('/admin/resource')``.

Application freezing
====================

Application can be used either as main app (``app.make_handler()``) or as
sub-application -- not both cases at the same time.

After connecting application by ``.add_subapp()`` call or starting
serving web-server as toplevel application the application is
**frozen**.

It means that registering new routes, signals and middlewares is
forbidden.  Changing state (``app['name'] = 'value'``) of frozen application is
deprecated and will be eventually removed.
