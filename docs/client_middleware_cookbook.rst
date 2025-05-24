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


Best Practices
--------------

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
