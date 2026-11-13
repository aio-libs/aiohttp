.. currentmodule:: aiohttp

.. _aiohttp-client-middleware-cookbook:

Client Middleware Cookbook
==========================

This cookbook provides examples of how client middlewares can be used for common use cases.

Simple Retry Middleware
-----------------------

It's very easy to create middlewares that can retry a connection on a given condition:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: retry_middleware

.. warning::

    It is recommended to ensure loops are bounded (e.g. using a ``for`` loop) to avoid
    creating an infinite loop.

Logging to an external service
------------------------------

If we needed to log our requests via an API call to an external server or similar, we could
create a simple middleware like this:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: api_logging_middleware

.. warning::

    Using the same session from within a middleware can cause infinite recursion if
    that request gets processed again by the middleware.

    To avoid such recursion a middleware should typically make requests with
    ``middlewares=()`` or else contain some condition to stop the request triggering
    the same logic when it is processed again by the middleware (e.g by whitelisting
    the API domain of the request).

Token Refresh Middleware
------------------------

If you need to refresh access tokens to continue accessing an API, this is also a good
candidate for a middleware. For example, you could check for a 401 response, then
refresh the token and retry:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: TokenRefresh401Middleware

If you have an expiry time for the token, you could refresh at the expiry time, to avoid the
failed request:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: TokenRefreshExpiryMiddleware

Or you could even refresh preemptively in a background task to avoid any API delays. This is probably more
efficient to implement without a middleware:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: token_refresh_preemptively_example
   :lines: 2-
   :dedent:

Or combine the above approaches to create a more robust solution.

.. note::

    These can also be adjusted to handle proxy auth by modifying
    :attr:`ClientRequest.proxy_headers`.

Server-side Request Forgery Protection
--------------------------------------

To provide protection against server-side request forgery, we could blacklist any internal
IPs or domains. We could create a middleware that rejects requests made to a blacklist:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: ssrf_middleware

.. warning::

   The above example is simplified for demonstration purposes. A production-ready
   implementation should also check IPv6 addresses (``::1``), private IP ranges,
   link-local addresses, and other internal hostnames. Consider using a well-tested
   library for SSRF protection in production environments.

If you know that your services correctly reject requests with an incorrect `Host` header, then
that may provide sufficient protection. Otherwise, we still have a concern with an attacker's
own domain resolving to a blacklisted IP. To provide complete protection, we can also
create a custom resolver:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: SSRFConnector

Using both of these together in a session should provide full SSRF protection.

Rate Limiting
-------------

To stay within a server's rate limit, a middleware can delay the requests that would
exceed it. The following middleware sends at most ``limit`` requests every ``period``
seconds for each key. By default, the key is the request's host:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: by_host

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: RateLimitMiddleware

Each request occupies one of its key's ``limit`` slots until ``period`` seconds after
it's sent. The first ``limit`` requests therefore go at once, and no window of ``period``
seconds ever holds more. For example, ``RateLimitMiddleware(10, 60)`` sends a burst of 10
requests immediately, and then never more than 10 in any minute. To space requests
evenly, use a ``limit`` of 1. A request that's cancelled while it waits, for example by
the ``total`` timeout, takes no slot.

The key can be any value usable as a dictionary key. To make the hostnames that resolve
to the same addresses share one limit, key requests by address:

.. literalinclude:: code/client_middleware_cookbook.py
   :pyobject: by_resolved_ip

``by_resolved_ip`` keeps each hostname's key from its first successful lookup on, even
if the DNS records change. Requests sent through a proxy keep their hostname as key,
because the proxy resolves it. Otherwise, hostnames that resolve to the same IPv4
addresses share a limit, and so do hostnames that resolve to the same IPv6 addresses
and have no IPv4 address. Hostnames whose answers only partly overlap can get separate
limits.

Pass ``by_resolved_ip`` the connector's resolver. Close that resolver yourself, because a
connector only closes the resolvers that it creates:

.. code-block:: python

   resolver = ThreadedResolver()
   rate_limit = RateLimitMiddleware(5, 1, key=by_resolved_ip(resolver))
   async with ClientSession(
       connector=TCPConnector(resolver=resolver), middlewares=(rate_limit,)
   ) as session:
       ...
   await resolver.close()

.. note::

   - To also count the requests that other middlewares send again, such as retries,
     place the rate limiter last in ``middlewares``. Redirects go through the
     middlewares too, so each hop counts as a request.
   - Time spent waiting for a slot counts toward the ``total`` timeout.
   - The limit holds when a request leaves the middleware, not when it reaches the
     server. Connection setup times can still bring requests closer together, so leave
     some headroom below the server's limit.
   - Share one instance between sessions, otherwise each session has its own allowance.
     Don't share it between event loops, because its semaphores bind to the event loop
     that first waits on them.


Best Practices
--------------

.. important::

   **Request-level middlewares replace session middlewares**: When you pass ``middlewares``
   to ``request()`` or its convenience methods (``get()``, ``post()``, etc.), it completely
   replaces the session-level middlewares, rather than extending them. This differs from
   other parameters like ``headers``, which are merged.

   .. code-block:: python

      session = ClientSession(middlewares=[middleware_session])

      # Session middleware is used
      await session.get("http://example.com")

      # Session middleware is NOT used, only request middleware
      await session.get("http://example.com", middlewares=[middleware_request])

      # To use both, explicitly pass both
      await session.get(
          "http://example.com",
          middlewares=[middleware_session, middleware_request]
      )

1. **Keep middleware focused**: Each middleware should have a single responsibility.

2. **Order matters**: Middlewares execute in the order they're listed. Place logging first,
   authentication before retry, etc.

3. **Avoid infinite recursion**: When making HTTP requests inside middleware, either:

   - Use ``middlewares=()`` to disable middleware for internal requests
   - Check the request URL/host to skip middleware for specific endpoints
   - Use a separate session for internal requests

4. **Handle errors gracefully**: Don't let middleware errors break the request flow unless
   absolutely necessary.

5. **Use bounded loops**: Always use ``for`` loops with a maximum iteration count instead
   of unbounded ``while`` loops to prevent infinite retries.

6. **Consider performance**: Each middleware adds overhead. For simple cases like adding
   static headers, consider using session or request parameters instead.

7. **Test thoroughly**: Middleware can affect all requests in subtle ways. Test edge cases
   like network errors, timeouts, and concurrent requests.

See Also
--------

- :ref:`aiohttp-client-middleware` - Core middleware documentation
- :ref:`aiohttp-client-advanced` - Advanced client usage
- :class:`DigestAuthMiddleware` - Built-in digest authentication middleware
