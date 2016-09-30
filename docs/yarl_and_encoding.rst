YARL and URL encoding
======================

Since aiohttp 1.1 the library uses :term:`yarl` for URL processing.


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
doesn't support *query args* but addding *args* is trivial:
``request.url_for('named_resource', param='a').with_query(arg='val')``.

The method returns a *relative* URL, absolute URL may be constructed by
``request.url.join(request.url_for(...)`` call.
