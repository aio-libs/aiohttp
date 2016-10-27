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

On server side has added :class:`web.Request.url` and
:class:`web.Request.rel_url` properties for representing relative and
absolute request's URL.

URL using is the recommended way, already existed properties for
retrieving URL parts are deprecated and will be eventually removed.

Redirection web exceptions accepts :class:`yarl.URL` as *location*
parameter. :class:`str` is still supported and will be supported forever.

Reverse URL processing for *router* has been changed.

The main API is :class:`aiohttp.web.Request.url_for(name, **kwargs)`
which returns a :class:`yarl.URL` instance for named resource. It
doesn't support *query args* but adding *args* is trivial:
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

Route matching also accepts both URL forms: raw and encoded.


Sub-Applications
----------------

Add sub application to route::

   subapp = web.Application()
   # setup subapp routes and middlewares

   app.add_subapp('/prefix/', subapp)

Middlewares and signals from ``app`` and ``subapp`` are chained.

Application can be used either as main app (``app.make_handler()``) or as
sub-application -- not both cases at the same time.

Url reversing for sub-applications should generate urls with proper prefix.

``SubAppResource`` is a regular prefixed resource with single route for
sinking every request into sub-application.
