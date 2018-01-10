.. _aiohttp-web-quickstart:

Web Server Quickstart
=====================

.. currentmodule:: aiohttp.web


Run a Simple Web Server
-----------------------

In order to implement a web server, first create a
:ref:`request handler <aiohttp-web-handler>`.

A request handler is a :ref:`coroutine <coroutine>` or regular function that
accepts a :class:`Request` instance as its only parameter and returns a
:class:`Response` instance::

   from aiohttp import web

   async def hello(request):
       return web.Response(text="Hello, world")

Next, create an :class:`Application` instance and register the
request handler with the application's :class:`router <UrlDispatcher>` on a
particular *HTTP method* and *path*::

   app = web.Application()
   app.router.add_get('/', hello)

After that, run the application by :func:`run_app` call::

   web.run_app(app)

That's it. Now, head over to ``http://localhost:8080/`` to see the results.

.. seealso::

   :ref:`aiohttp-web-graceful-shutdown` section explains what :func:`run_app`
   does and how to implement complex server initialization/finalization
   from scratch.

   :ref:`aiohttp-web-app-runners` for more handling more complex cases
   like *asynchronous* web application serving and multiple hosts
   support.

.. _aiohttp-web-cli:

Command Line Interface (CLI)
----------------------------
:mod:`aiohttp.web` implements a basic CLI for quickly serving an
:class:`Application` in *development* over TCP/IP:

.. code-block:: shell

    $ python -m aiohttp.web -H localhost -P 8080 package.module:init_func

``package.module:init_func`` should be an importable :term:`callable` that
accepts a list of any non-parsed command-line arguments and returns an
:class:`Application` instance after setting it up::

    def init_func(argv):
        app = web.Application()
        app.router.add_get("/", index_handler)
        return app


.. _aiohttp-web-handler:

Handler
-------

A request handler can be any :term:`callable` that accepts a :class:`Request`
instance as its only argument and returns a :class:`StreamResponse` derived
(e.g. :class:`Response`) instance::

   def handler(request):
       return web.Response()

A handler **may** also be a :ref:`coroutine<coroutine>`, in which case
:mod:`aiohttp.web` will ``await`` the handler::

   async def handler(request):
       return web.Response()

Handlers are setup to handle requests by registering them with the
:attr:`Application.router` on a particular route (*HTTP method* and
*path* pair) using methods like :class:`UrlDispatcher.add_get` and
:class:`UrlDispatcher.add_post`::

   app.router.add_get('/', handler)
   app.router.add_post('/post', post_handler)
   app.router.add_put('/put', put_handler)

:meth:`~UrlDispatcher.add_route` also supports the wildcard *HTTP method*,
allowing a handler to serve incoming requests on a *path* having **any**
*HTTP method*::

  app.router.add_route('*', '/path', all_handler)

The *HTTP method* can be queried later in the request handler using the
:attr:`Request.method` property.

By default endpoints added with :meth:`~UrlDispatcher.add_get` will accept
``HEAD`` requests and return the same response headers as they would
for a ``GET`` request. You can also deny ``HEAD`` requests on a route::

   app.router.add_get('/', handler, allow_head=False)

Here ``handler`` won't be called and the server will response with ``405``.

.. note::

   This is a change as of **aiohttp v2.0** to act in accordance with
   `RFC 7231 <https://tools.ietf.org/html/rfc7231#section-4.3.2>`_.

   Previous version always returned ``405`` for ``HEAD`` requests
   to routes added with :meth:`~UrlDispatcher.add_get`.

If you have handlers which perform lots of processing to write the response
body you may wish to improve performance by skipping that processing
in the case of ``HEAD`` requests while still taking care to respond with
the same headers as with ``GET`` requests.

.. _aiohttp-web-resource-and-route:

Resources and Routes
--------------------

Internally *router* is a list of *resources*.

Resource is an entry in *route table* which corresponds to requested URL.

Resource in turn has at least one *route*.

Route corresponds to handling *HTTP method* by calling *web handler*.

:meth:`UrlDispatcher.add_get` / :meth:`UrlDispatcher.add_post` and
family are plain shortcuts for :meth:`UrlDispatcher.add_route`.

:meth:`UrlDispatcher.add_route` in turn is just a shortcut for pair of
:meth:`UrlDispatcher.add_resource` and :meth:`Resource.add_route`::

   resource = app.router.add_resource(path, name=name)
   route = resource.add_route(method, handler)
   return route

.. seealso::

   :ref:`aiohttp-router-refactoring-021` for more details


.. _aiohttp-web-variable-handler:

Variable Resources
^^^^^^^^^^^^^^^^^^

Resource may have *variable path* also. For instance, a resource with
the path ``'/a/{name}/c'`` would match all incoming requests with
paths such as ``'/a/b/c'``, ``'/a/1/c'``, and ``'/a/etc/c'``.

A variable *part* is specified in the form ``{identifier}``, where the
``identifier`` can be used later in a
:ref:`request handler <aiohttp-web-handler>` to access the matched value for
that *part*. This is done by looking up the ``identifier`` in the
:attr:`Request.match_info` mapping::

   async def variable_handler(request):
       return web.Response(
           text="Hello, {}".format(request.match_info['name']))

   resource = app.router.add_resource('/{name}')
   resource.add_route('GET', variable_handler)

By default, each *part* matches the regular expression ``[^{}/]+``.

You can also specify a custom regex in the form ``{identifier:regex}``::

   resource = app.router.add_resource(r'/{name:\d+}')

.. note::

   Regex should match against *percent encoded* URL
   (``request.raw_path``). E.g. *space character* is encoded
   as ``%20``.

   According to
   `RFC 3986 <https://tools.ietf.org/html/rfc3986.html#appendix-A>`_
   allowed in path symbols are::

      allowed       = unreserved / pct-encoded / sub-delims
                    / ":" / "@" / "/"

      pct-encoded   = "%" HEXDIG HEXDIG

      unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"

      sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                    / "*" / "+" / "," / ";" / "="

.. _aiohttp-web-named-routes:

Reverse URL Constructing using Named Resources
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Routes can also be given a *name*::

   resource = app.router.add_resource('/root', name='root')

Which can then be used to access and build a *URL* for that resource later (e.g.
in a :ref:`request handler <aiohttp-web-handler>`)::

   >>> request.app.router['root'].url_for().with_query({"a": "b", "c": "d"})
   URL('/root?a=b&c=d')

A more interesting example is building *URLs* for :ref:`variable
resources <aiohttp-web-variable-handler>`::

   app.router.add_resource(r'/{user}/info', name='user-info')


In this case you can also pass in the *parts* of the route::

   >>> request.app.router['user-info'].url_for(user='john_doe')\
   ...                                         .with_query("a=b")
   '/john_doe/info?a=b'


Organizing Handlers in Classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As discussed above, :ref:`handlers <aiohttp-web-handler>` can be first-class
functions or coroutines::

   async def hello(request):
       return web.Response(text="Hello, world")

   app.router.add_get('/', hello)

But sometimes it's convenient to group logically similar handlers into a Python
*class*.

Since :mod:`aiohttp.web` does not dictate any implementation details,
application developers can organize handlers in classes if they so wish::

   class Handler:

       def __init__(self):
           pass

       def handle_intro(self, request):
           return web.Response(text="Hello, world")

       async def handle_greeting(self, request):
           name = request.match_info.get('name', "Anonymous")
           txt = "Hello, {}".format(name)
           return web.Response(text=txt)

   handler = Handler()
   app.router.add_get('/intro', handler.handle_intro)
   app.router.add_get('/greet/{name}', handler.handle_greeting)


.. _aiohttp-web-class-based-views:

Class Based Views
^^^^^^^^^^^^^^^^^

:mod:`aiohttp.web` has support for django-style class based views.

You can derive from :class:`View` and define methods for handling http
requests::

   class MyView(web.View):
       async def get(self):
           return await get_resp(self.request)

       async def post(self):
           return await post_resp(self.request)

Handlers should be coroutines accepting self only and returning
response object as regular :term:`web-handler`. Request object can be
retrieved by :attr:`View.request` property.

After implementing the view (``MyView`` from example above) should be
registered in application's router::

   app.router.add_view('/path/to', MyView)

Example will process GET and POST requests for */path/to* but raise
*405 Method not allowed* exception for unimplemented HTTP methods.

Resource Views
^^^^^^^^^^^^^^

*All* registered resources in a router can be viewed using the
:meth:`UrlDispatcher.resources` method::

   for resource in app.router.resources():
       print(resource)

Similarly, a *subset* of the resources that were registered with a *name* can be
viewed using the :meth:`UrlDispatcher.named_resources` method::

   for name, resource in app.router.named_resources().items():
       print(name, resource)


.. _aiohttp-web-alternative-routes-definition:

Alternative ways for registering routes
---------------------------------------

Code examples shown above use *imperative* style for adding new
routes: they call ``app.router.add_get(...)`` etc.

There are two alternatives: route tables and route decorators.

Route tables look like Django way::

   async def handle_get(request):
       ...


   async def handle_post(request):
       ...

   app.router.add_routes([web.get('/get', handle_get),
                          web.post('/post', handle_post),


The snippet calls :meth:`~aiohttp.web.UrlDispather.add_routes` to
register a list of *route definitions* (:class:`aiohttp.web.RouteDef`
instances) created by :func:`aiohttp.web.get` or
:func:`aiohttp.web.post` functions.

.. seealso:: :ref:`aiohttp-web-route-def` reference.

Route decorators are closer to Flask approach::

   routes = web.RouteTableDef()

   @routes.get('/get')
   async def handle_get(request):
       ...


   @routes.post('/post')
   async def handle_post(request):
       ...

   app.router.add_routes(routes)

It is also possible to use decorators with class-based views::

   routes = web.RouteTableDef()

   @routes.view("/view")
   class MyView(web.View):
       async def get(self):
           ...

       async def post(self):
           ...

   app.router.add_routes(routes)

The example creates a :class:`aiohttp.web.RouteTableDef` container first.

The container is a list-like object with additional decorators
:meth:`aiohttp.web.RouteTableDef.get`,
:meth:`aiohttp.web.RouteTableDef.post` etc. for registering new
routes.

After filling the container
:meth:`~aiohttp.web.UrlDispather.add_routes` is used for adding
registered *route definitions* into application's router.

.. seealso:: :ref:`aiohttp-web-route-table-def` reference.

All tree ways (imperative calls, route tables and decorators) are
equivalent, you could use what do you prefer or even mix them on your
own.

.. versionadded:: 2.3

JSON Response
-------------

It is a common case to return JSON data in response, :mod:`aiohttp.web`
provides a shortcut for returning JSON -- :func:`aiohttp.web.json_response`::

   def handler(request):
       data = {'some': 'data'}
       return web.json_response(data)

The shortcut method returns :class:`aiohttp.web.Response` instance
so you can for example set cookies before returning it from handler.


User Sessions
-------------

Often you need a container for storing user data across requests. The concept
is usually called a *session*.

:mod:`aiohttp.web` has no built-in concept of a *session*, however, there is a
third-party library, :mod:`aiohttp_session`, that adds *session* support::

    import asyncio
    import time
    import base64
    from cryptography import fernet
    from aiohttp import web
    from aiohttp_session import setup, get_session, session_middleware
    from aiohttp_session.cookie_storage import EncryptedCookieStorage

    async def handler(request):
        session = await get_session(request)
        last_visit = session['last_visit'] if 'last_visit' in session else None
        text = 'Last visited: {}'.format(last_visit)
        return web.Response(text=text)

    def make_app():
        app = web.Application()
        # secret_key must be 32 url-safe base64-encoded bytes
        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        setup(app, EncryptedCookieStorage(secret_key))
        app.router.add_route('GET', '/', handler)
        return app

    web.run_app(make_app())


.. _aiohttp-web-forms:

HTTP Forms
----------

HTTP Forms are supported out of the box.

If form's method is ``"GET"`` (``<form method="get">``) use
:attr:`Request.query` for getting form data.

To access form data with ``"POST"`` method use
:meth:`Request.post` or :meth:`Request.multipart`.

:meth:`Request.post` accepts both
``'application/x-www-form-urlencoded'`` and ``'multipart/form-data'``
form's data encoding (e.g. ``<form enctype="multipart/form-data">``).
It stores files data in temporary directory. If `client_max_size` is
specified `post` raises `ValueError` exception.
For efficiency use :meth:`Request.multipart`, It is especially effective
for uploading large files (:ref:`aiohttp-web-file-upload`).

Values submitted by the following form:

.. code-block:: html

   <form action="/login" method="post" accept-charset="utf-8"
         enctype="application/x-www-form-urlencoded">

       <label for="login">Login</label>
       <input id="login" name="login" type="text" value="" autofocus/>
       <label for="password">Password</label>
       <input id="password" name="password" type="password" value=""/>

       <input type="submit" value="login"/>
   </form>

could be accessed as::

    async def do_login(request):
        data = await request.post()
        login = data['login']
        password = data['password']


.. _aiohttp-web-file-upload:

File Uploads
------------

:mod:`aiohttp.web` has built-in support for handling files uploaded from the
browser.

First, make sure that the HTML ``<form>`` element has its *enctype* attribute
set to ``enctype="multipart/form-data"``. As an example, here is a form that
accepts an MP3 file:

.. code-block:: html

   <form action="/store/mp3" method="post" accept-charset="utf-8"
         enctype="multipart/form-data">

       <label for="mp3">Mp3</label>
       <input id="mp3" name="mp3" type="file" value=""/>

       <input type="submit" value="submit"/>
   </form>

Then, in the :ref:`request handler <aiohttp-web-handler>` you can access the
file input field as a :class:`FileField` instance. :class:`FileField` is simply
a container for the file as well as some of its metadata::

    async def store_mp3_handler(request):

        # WARNING: don't do that if you plan to receive large files!
        data = await request.post()

        mp3 = data['mp3']

        # .filename contains the name of the file in string format.
        filename = mp3.filename

        # .file contains the actual file data that needs to be stored somewhere.
        mp3_file = data['mp3'].file

        content = mp3_file.read()

        return web.Response(body=content,
                            headers=MultiDict(
                                {'CONTENT-DISPOSITION': mp3_file}))


You might have noticed a big warning in the example above. The general issue is
that :meth:`Request.post` reads the whole payload in memory, resulting in possible
:abbr:`OOM (Out Of Memory)` errors. To avoid this, for multipart uploads, you
should use :meth:`Request.multipart` which returns a :ref:`multipart reader
<aiohttp-multipart>`::

    async def store_mp3_handler(request):

        reader = await request.multipart()

        # /!\ Don't forget to validate your inputs /!\

        # reader.next() will `yield` the fields of your form

        field = await reader.next()
        assert field.name == 'name'
        name = await field.read(decode=True)

        field = await reader.next()
        assert field.name == 'mp3'
        filename = field.filename
        # You cannot rely on Content-Length if transfer is chunked.
        size = 0
        with open(os.path.join('/spool/yarrr-media/mp3/', filename), 'wb') as f:
            while True:
                chunk = await field.read_chunk()  # 8192 bytes by default.
                if not chunk:
                    break
                size += len(chunk)
                f.write(chunk)

        return web.Response(text='{} sized of {} successfully stored'
                                 ''.format(filename, size))

.. _aiohttp-web-websockets:

WebSockets
----------

:mod:`aiohttp.web` supports *WebSockets* out-of-the-box.

To setup a *WebSocket*, create a :class:`WebSocketResponse` in a
:ref:`request handler <aiohttp-web-handler>` and then use it to communicate
with the peer::

    async def websocket_handler(request):

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == 'close':
                    await ws.close()
                else:
                    await ws.send_str(msg.data + '/answer')
            elif msg.type == aiohttp.WSMsgType.ERROR:
                print('ws connection closed with exception %s' %
                      ws.exception())

        print('websocket connection closed')

        return ws

The handler should be registered as HTTP GET processor::

    app.router.add_get('/ws', websocket_handler)


.. _aiohttp-web-exceptions:

Exceptions
----------

:mod:`aiohttp.web` defines a set of exceptions for every *HTTP status code*.

Each exception is a subclass of :class:`~HTTPException` and relates to a single
HTTP status code.

The exceptions are also a subclass of :class:`Response`, allowing you to either
``raise`` or ``return`` them in a
:ref:`request handler <aiohttp-web-handler>` for the same effect.

.. warning::

   Returning :class:`~HTTPException` or its subclasses is deprecated and will
   be removed in subsequent aiohttp versions.

The following snippets are the same::

    async def handler(request):
        return aiohttp.web.HTTPFound('/redirect')

and::

    async def handler(request):
        raise aiohttp.web.HTTPFound('/redirect')


Each exception class has a status code according to :rfc:`2068`:
codes with 100-300 are not really errors; 400s are client errors,
and 500s are server errors.

HTTP Exception hierarchy chart::

   Exception
     HTTPException
       HTTPSuccessful
         * 200 - HTTPOk
         * 201 - HTTPCreated
         * 202 - HTTPAccepted
         * 203 - HTTPNonAuthoritativeInformation
         * 204 - HTTPNoContent
         * 205 - HTTPResetContent
         * 206 - HTTPPartialContent
       HTTPRedirection
         * 300 - HTTPMultipleChoices
         * 301 - HTTPMovedPermanently
         * 302 - HTTPFound
         * 303 - HTTPSeeOther
         * 304 - HTTPNotModified
         * 305 - HTTPUseProxy
         * 307 - HTTPTemporaryRedirect
         * 308 - HTTPPermanentRedirect
       HTTPError
         HTTPClientError
           * 400 - HTTPBadRequest
           * 401 - HTTPUnauthorized
           * 402 - HTTPPaymentRequired
           * 403 - HTTPForbidden
           * 404 - HTTPNotFound
           * 405 - HTTPMethodNotAllowed
           * 406 - HTTPNotAcceptable
           * 407 - HTTPProxyAuthenticationRequired
           * 408 - HTTPRequestTimeout
           * 409 - HTTPConflict
           * 410 - HTTPGone
           * 411 - HTTPLengthRequired
           * 412 - HTTPPreconditionFailed
           * 413 - HTTPRequestEntityTooLarge
           * 414 - HTTPRequestURITooLong
           * 415 - HTTPUnsupportedMediaType
           * 416 - HTTPRequestRangeNotSatisfiable
           * 417 - HTTPExpectationFailed
           * 421 - HTTPMisdirectedRequest
           * 422 - HTTPUnprocessableEntity
           * 424 - HTTPFailedDependency
           * 426 - HTTPUpgradeRequired
           * 428 - HTTPPreconditionRequired
           * 429 - HTTPTooManyRequests
           * 431 - HTTPRequestHeaderFieldsTooLarge
           * 451 - HTTPUnavailableForLegalReasons
         HTTPServerError
           * 500 - HTTPInternalServerError
           * 501 - HTTPNotImplemented
           * 502 - HTTPBadGateway
           * 503 - HTTPServiceUnavailable
           * 504 - HTTPGatewayTimeout
           * 505 - HTTPVersionNotSupported
           * 506 - HTTPVariantAlsoNegotiates
           * 507 - HTTPInsufficientStorage
           * 510 - HTTPNotExtended
           * 511 - HTTPNetworkAuthenticationRequired

All HTTP exceptions have the same constructor signature::

    HTTPNotFound(*, headers=None, reason=None,
                 body=None, text=None, content_type=None)

If not directly specified, *headers* will be added to the *default
response headers*.

Classes :class:`HTTPMultipleChoices`, :class:`HTTPMovedPermanently`,
:class:`HTTPFound`, :class:`HTTPSeeOther`, :class:`HTTPUseProxy`,
:class:`HTTPTemporaryRedirect` have the following constructor signature::

    HTTPFound(location, *, headers=None, reason=None,
              body=None, text=None, content_type=None)

where *location* is value for *Location HTTP header*.

:class:`HTTPMethodNotAllowed` is constructed by providing the incoming
unsupported method and list of allowed methods::

    HTTPMethodNotAllowed(method, allowed_methods, *,
                         headers=None, reason=None,
                         body=None, text=None, content_type=None)


