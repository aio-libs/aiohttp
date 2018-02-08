.. _aiohttp-client-tracing-reference:

Tracing Reference
=================

.. currentmodule:: aiohttp

.. versionadded:: 3.0

A reference for client tracing API.

.. seealso:: :ref:`aiohttp-client-tracing` for tracing usage instructions.

TraceConfig
-----------


.. class:: TraceConfig(trace_config_ctx_factory=SimpleNamespace)

   Trace config is the configuration object used to trace requests
   launched by a :class:`ClientSession` object using different events
   related to different parts of the request flow.

   :param trace_config_ctx_factory: factory used to create trace contexts,
      default class used :class:`types.SimpleNamespace`

   .. method:: trace_config_ctx(trace_request_ctx=None)

      :param trace_request_ctx: Will be used to pass as a kw for the
        ``trace_config_ctx_factory``.

      Build a new trace context from the config.

   Every signal handler should have the following signature::

      async def on_signal(session, context, params): ...

   where ``session`` is :class:`ClientSession` instance, ``context`` is an
   object returned by :meth:`trace_config_ctx` call and ``params`` is a
   data class with signal parameters. The type of ``params`` depends on
   subscribed signal and described below.

   .. attribute:: on_request_start

      Property that gives access to the signals that will be executed
      when a request starts.

      ``params`` is :class:`aiohttp.TraceRequestStartParams` instance.

   .. attribute:: on_request_redirect

      Property that gives access to the signals that will be executed when a
      redirect happens during a request flow.

      ``params`` is :class:`aiohttp.TraceRequestRedirectParams` instance.

   .. attribute:: on_request_end

      Property that gives access to the signals that will be executed when a
      request ends.

      ``params`` is :class:`aiohttp.TraceRequestEndParams` instance.

   .. attribute:: on_request_exception

      Property that gives access to the signals that will be executed when a
      request finishes with an exception.

      ``params`` is :class:`aiohttp.TraceRequestExceptionParams` instance.

   .. attribute:: on_connection_queued_start

      Property that gives access to the signals that will be executed when a
      request has been queued waiting for an available connection.

      ``params`` is :class:`aiohttp.TraceConnectionQueuedStartParams`
      instance.

   .. attribute:: on_connection_queued_end

      Property that gives access to the signals that will be executed when a
      request that was queued already has an available connection.

      ``params`` is :class:`aiohttp.TraceConnectionQueuedEndParams`
      instance.

   .. attribute:: on_connection_create_start

      Property that gives access to the signals that will be executed when a
      request creates a new connection.

      ``params`` is :class:`aiohttp.TraceConnectionCreateStartParams`
      instance.

   .. attribute:: on_connection_create_end

      Property that gives access to the signals that will be executed when a
      request that created a new connection finishes its creation.

      ``params`` is :class:`aiohttp.TraceConnectionCreateEndParams`
      instance.

   .. attribute:: on_connection_reuseconn

      Property that gives access to the signals that will be executed when a
      request reuses a connection.

      ``params`` is :class:`aiohttp.TraceConnectionReuseconnParams`
      instance.

   .. attribute:: on_dns_resolvehost_start

      Property that gives access to the signals that will be executed when a
      request starts to resolve the domain related with the request.

      ``params`` is :class:`aiohttp.TraceDnsResolveHostStartParams`
      instance.

   .. attribute:: on_dns_resolvehost_end

      Property that gives access to the signals that will be executed when a
      request finishes to resolve the domain related with the request.

      ``params`` is :class:`aiohttp.TraceDnsResolveHostEndParams` instance.

   .. attribute:: on_dns_cache_hit

      Property that gives access to the signals that will be executed when a
      request was able to use a cached DNS resolution for the domain related
      with the request.

      ``params`` is :class:`aiohttp.TraceDnsCacheHitParams` instance.

   .. attribute:: on_dns_cache_miss

      Property that gives access to the signals that will be executed when a
      request was not able to use a cached DNS resolution for the domain related
      with the request.

      ``params`` is :class:`aiohttp.TraceDnsCacheMissParams` instance.


TraceRequestStartParams
-----------------------

.. class:: TraceRequestStartParams

   See :attr:`TraceConfig.on_request_start` for details.

   .. attribute:: method

       Method that will be used  to make the request.

   .. attribute:: url

       URL that will be used  for the request.

   .. attribute:: headers

       Headers that will be used for the request, can be mutated.

TraceRequestEndParams
---------------------

.. class:: TraceRequestEndParams

   See :attr:`TraceConfig.on_request_end` for details.

   .. attribute:: method

       Method used to make the request.

   .. attribute:: url

       URL used for the request.

   .. attribute:: headers

       Headers used for the request.

   .. attribute:: response

       Response :class:`ClientResponse`.


TraceRequestExceptionParams
---------------------------

.. class:: TraceRequestExceptionParams

   See :attr:`TraceConfig.on_request_exception` for details.

   .. attribute:: method

       Method used to make the request.

   .. attribute:: url

       URL used for the request.

   .. attribute:: headers

       Headers used for the request.

   .. attribute:: exception

       Exception raised during the request.

TraceRequestRedirectParams
--------------------------

.. class:: TraceRequestRedirectParams

   See :attr:`TraceConfig.on_request_redirect` for details.

   .. attribute:: method

       Method used to get this redirect request.

   .. attribute:: url

       URL used for this redirect request.

   .. attribute:: headers

       Headers used for this redirect.

   .. attribute:: response

       Response :class:`ClientResponse` got from the redirect.

TraceConnectionQueuedStartParams
--------------------------------

.. class:: TraceConnectionQueuedStartParams

   See :attr:`TraceConfig.on_connection_queued_start` for details.

   There are no attributes right now.

TraceConnectionQueuedEndParams
------------------------------

.. class:: TraceConnectionQueuedEndParams

   See :attr:`TraceConfig.on_connection_queued_end` for details.

   There are no attributes right now.

TraceConnectionCreateStartParams
--------------------------------

.. class:: TraceConnectionCreateStartParams

   See :attr:`TraceConfig.on_connection_create_start` for details.

   There are no attributes right now.

TraceConnectionCreateEndParams
------------------------------

.. class:: TraceConnectionCreateEndParams

   See :attr:`TraceConfig.on_connection_create_end` for details.

   There are no attributes right now.

TraceConnectionReuseconnParams
------------------------------

.. class:: TraceConnectionReuseconnParams

   See :attr:`TraceConfig.on_connection_reuseconn` for details.

   There are no attributes right now.

TraceDnsResolveHostStartParams
------------------------------

.. class:: TraceDnsResolveHostStartParams

   See :attr:`TraceConfig.on_dns_resolvehost_start` for details.

   .. attribute:: Host

       Host that will be resolved.

TraceDnsResolveHostEndParams
----------------------------

.. class:: TraceDnsResolveHostEndParams

   See :attr:`TraceConfig.on_dns_resolvehost_end` for details.

   .. attribute:: Host

       Host that has been resolved.

TraceDnsCacheHitParams
----------------------

.. class:: TraceDnsCacheHitParams

   See :attr:`TraceConfig.on_dns_cache_hit` for details.

   .. attribute:: Host

       Host found in the cache.

TraceDnsCacheMissParams
-----------------------

.. class:: TraceDnsCacheMissParams

   See :attr:`TraceConfig.on_dns_cache_miss` for details.

   .. attribute:: Host

       Host didn't find the cache.
