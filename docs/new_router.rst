.. _aiohttp-router-refactoring-021:

Router refactoring in 0.21
==========================

Rationale
---------

First generation (v1) of router has mapped ``(method, path)`` pair to
:term:`web-handler`.  Mapping is named **route**. Routes used to have
unique names if any.

The main mistake with the design is coupling the **route** to
``(method, path)`` pair while really URL construction operates with
**resources** (**location** is a synonym). HTTP method is not part of URI
but applied on sending HTTP request only.

Having different **route names** for the same path is confusing. Moreover
**named routes** constructed for the same path should have unique
non overlapping names which is cumbersome is certain situations.

From other side sometimes it's desirable to bind several HTTP methods
to the same web handler. For *v1* router it can be solved by passing '*'
as HTTP method. Class based views require '*' method also usually.


Implementation
--------------

The change introduces **resource** as first class citizen::

   resource = router.add_resource('/path/{to}', name='name')

*Resource* has a **path** (dynamic or constant) and optional **name**.

The name is **unique** in router context.

*Resource* has **routes**.

*Route* corresponds to *HTTP method* and :term:`web-handler` for the method::

   route = resource.add_route('GET', handler)

User still may use wildcard for accepting all HTTP methods (maybe we
will add something like ``resource.add_wildcard(handler)`` later).

Since **names** belongs to **resources** now ``app.router['name']``
returns a **resource** instance instead of :class:`aiohttp.web.Route`.

**resource** has ``.url()`` method, so
``app.router['name'].url(parts={'a': 'b'}, query={'arg': 'param'})``
still works as usual.


The change allows to rewrite static file handling and implement nested
applications as well.

Decoupling of *HTTP location* and *HTTP method* makes life easier.

Backward compatibility
----------------------

The refactoring is 99% compatible with previous implementation.

99% means all example and the most of current code works without
modifications but we have subtle API backward incompatibles.

``app.router['name']`` returns a :class:`aiohttp.web.BaseResource`
instance instead of :class:`aiohttp.web.Route` but resource has the
same ``resource.url(...)`` most useful method, so end user should feel no
difference.

``route.match(...)`` is **not** supported anymore, use
:meth:`aiohttp.web.AbstractResource.resolve` instead.

``app.router.add_route(method, path, handler, name='name')`` now is just
shortcut for::

    resource = app.router.add_resource(path, name=name)
    route = resource.add_route(method, handler)
    return route

``app.router.register_route(...)`` is still supported, it creates
:class:`aiohttp.web.ResourceAdapter` for every call (but it's deprecated now).


.. disqus::
  :title: aiohttp router refactoring notes
