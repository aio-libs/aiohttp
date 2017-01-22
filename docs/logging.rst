.. _aiohttp-logging:

Logging
=======

.. currentmodule:: aiohttp


*aiohttp* uses standard :mod:`logging` for tracking the
library activity.

We have the following loggers enumerated by names:

- ``'aiohttp.access'``
- ``'aiohttp.client'``
- ``'aiohttp.internal'``
- ``'aiohttp.server'``
- ``'aiohttp.web'``
- ``'aiohttp.websocket'``

You may subscribe to these loggers for getting logging messages.  The
page does not provide instructions for logging subscribing while the
most friendly method is :func:`logging.config.dictConfig` for
configuring whole loggers in your application.



Access logs
-----------

Access log by default is switched on and uses ``'aiohttp.access'``
logger name.

The log may be controlled by :meth:`aiohttp.web.Application.make_handler` call.

Pass *access_log* parameter with value of :class:`logging.Logger`
instance to override default logger.

.. note::

   Use ``app.make_handler(access_log=None)`` for disabling access logs.


Other parameter called *access_log_format* may be used for specifying log
format (see below).


.. _aiohttp-logging-access-log-format-spec:

Format specification
^^^^^^^^^^^^^^^^^^^^

The library provides custom micro-language to specifying info about
request and response:

+--------------+---------------------------------------------------------+
| Option       | Meaning                                                 |
+==============+=========================================================+
| ``%%``       | The percent sign                                        |
+--------------+---------------------------------------------------------+
| ``%a``       | Remote IP-address                                       |
|              | (IP-address of proxy if using reverse proxy)            |
+--------------+---------------------------------------------------------+
| ``%t``       | Time when the request was started to process            |
+--------------+---------------------------------------------------------+
| ``%P``       | The process ID of the child that serviced the request   |
+--------------+---------------------------------------------------------+
| ``%r``       | First line of request                                   |
+--------------+---------------------------------------------------------+
| ``%s``       | Response status code                                    |
+--------------+---------------------------------------------------------+
| ``%b``       | Size of response in bytes, excluding HTTP headers       |
+--------------+---------------------------------------------------------+
| ``%O``       | Bytes sent, including headers                           |
+--------------+---------------------------------------------------------+
| ``%T``       | The time taken to serve the request, in seconds         |
+--------------+---------------------------------------------------------+
| ``%Tf``      | The time taken to serve the request, in seconds         |
|              | with fraction in %.06f format                           |
+--------------+---------------------------------------------------------+
| ``%D``       | The time taken to serve the request, in microseconds    |
+--------------+---------------------------------------------------------+
| ``%{FOO}i``  | ``request.headers['FOO']``                              |
+--------------+---------------------------------------------------------+
| ``%{FOO}o``  | ``response.headers['FOO']``                             |
+--------------+---------------------------------------------------------+
| ``%{FOO}e``  | ``os.environ['FOO']``                                   |
+--------------+---------------------------------------------------------+

Default access log format is::

   '%a %l %u %t "%r" %s %b "%{Referrer}i" "%{User-Agent}i"'


.. note::

   When `Gunicorn <http://docs.gunicorn.org/en/latest/index.html>`_ is used for
   :ref:`deployment <aiohttp-deployment-gunicorn>` its default access log format
   will be automatically replaced with the default aiohttp's access log format.

   If Gunicorn's option access_logformat_ is
   specified explicitly it should use aiohttp's format specification.


Error logs
----------

*aiohttp.web* uses logger named ``'aiohttp.server'`` to store errors
given on web requests handling.

The log is enabled by default.

To use different logger name please specify *logger* parameter
(:class:`logging.Logger` instance) on performing
:meth:`aiohttp.web.Application.make_handler` call.


.. _access_logformat:
    http://docs.gunicorn.org/en/stable/settings.html#access-log-format


.. disqus::
  :title: aiohttp logging
