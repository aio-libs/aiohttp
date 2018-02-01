.. _aiohttp-tracing-reference:

Tracing Reference
=================

.. module:: aiohttp
.. currentmodule:: aiohttp


TraceConfig
-----------

Trace config is the configuration object used to trace requests launched by
a Client session object using different events related to different parts of
the request flow.

.. class:: TraceConfig(trace_config_ctx_factory=SimpleNamespace)

   :param trace_config_ctx_factory: factory used to create trace contexts,
      default class used :class:`SimpleNamespace`

   .. method:: trace_config_ctx(trace_request_ctx=None)

      :param trace_request_ctx: Will be used to pass as a kw for the
        ``trace_config_ctx_factory``.

      Return a new trace context.

   .. attribute:: on_request_start

      Property that gives access to the signals that will be executed when a
      request starts, based on the :class:`aiohttp.signals.Signal` implementation.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceRequestStartParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_request_redirect

      Property that gives access to the signals that will be executed when a
      redirect happens during a request flow.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceRequestRedirectParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_request_end

      Property that gives access to the signals that will be executed when a
      request ends.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceRequestEndParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_request_exception

      Property that gives access to the signals that will be executed when a
      request finishes with an exception.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceRequestExceptionParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_connection_queued_start

      Property that gives access to the signals that will be executed when a
      request has been queued waiting for an available connection.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceConnectionQueuedStartParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_connection_queued_end

      Property that gives access to the signals that will be executed when a
      request that was queued already has an available connection.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceConnectionQueuedEndParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_connection_create_start

      Property that gives access to the signals that will be executed when a
      request creates a new connection.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceConnectionCreateStartParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_connection_create_end

      Property that gives access to the signals that will be executed when a
      request that created a new connection finishes its creation.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceConnectionCreateEndParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_connection_reuseconn

      Property that gives access to the signals that will be executed when a
      request reuses a connection.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceConnectionReuseconnParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_dns_resolvehost_start

      Property that gives access to the signals that will be executed when a
      request starts to resolve the domain related with the request.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceDnsResolveHostStartParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_dns_resolvehost_end

      Property that gives access to the signals that will be executed when a
      request finishes to resolve the domain related with the request.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceDnsResolveHostEndParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_dns_cache_hit

      Property that gives access to the signals that will be executed when a
      request was able to use a cached DNS resolution for the domain related
      with the request.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceDnsCacheHitParams` instance

      .. versionadded:: 3.0

   .. attribute:: on_dns_cache_miss

      Property that gives access to the signals that will be executed when a
      request was not able to use a cached DNS resolution for the domain related
      with the request.

      The signal handler signature is ``async def on_request_start(session, context, params): ...``
      where ``params`` is :class:`aiohttp.TraceDnsCacheMissParams` instance

      .. versionadded:: 3.0

.. class:: TraceRequestStartParams

   .. attribute:: method 

       Method that will be used  to make the request.

   .. attribute:: url

       URL that will be used  for the request.

   .. attribute:: headers

       Headers that will be used for the request, can be mutated.

.. class:: TraceRequestEndParams

   .. attribute:: method 

       Method used to make the request.

   .. attribute:: url

       URL used for the request.

   .. attribute:: headers

       Headers used for the request.

   .. attribute:: resp

       Response :class:`ClientReponse`.


.. class:: TraceRequestExceptionParams

   .. attribute:: method 

       Method used to make the request.

   .. attribute:: url

       URL used for the request.

   .. attribute:: headers

       Headers used for the request.

   .. attribute:: exception

       Exception raised during the request.

.. class:: TraceRequestRedirectParams

   .. attribute:: method 

       Method used to get this redirect request.

   .. attribute:: url

       URL used for this redirect request.

   .. attribute:: headers

       Headers used for this redirect.

   .. attribute:: resp

       Response :class:`ClientReponse` got from the redirect.

.. class:: TraceConnectionQueuedStartParams

       There are no attributes right now.

.. class:: TraceConnectionQueuedEndParams

       There are no attributes right now.

.. class:: TraceConnectionCreateStartParams

       There are no attributes right now.

.. class:: TraceConnectionCreateEndParams

       There are no attributes right now.

.. class:: TraceConnectionReuseconnParams

       There are no attributes right now.

.. class:: TraceDnsResolveHostStartParams

   .. attribute:: Host

       Host that will be resolved.

.. class:: TraceDnsResolveHostEndParams

   .. attribute:: Host

       Host that has been resolved.

.. class:: TraceDnsCacheHitParams

   .. attribute:: Host

       Host found in the cache.

.. class:: TraceDnsCacheMissParams

   .. attribute:: Host

       Host didn't find the cache.
