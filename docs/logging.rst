.. _aiohttp-logging:

Logging
=======

.. highlight:: python

.. currentmodule:: aiohttp


*aiohttp* uses standard :mod:`logging` for tracking the
library activity.

We have the following loggers enumerated by names:

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

Access log is enabled by specifying *access_log* parameter
(:class:`logging.Logger` instance) on
:meth:`aiohttp.web.Application.make_handler` call.

Optional *access_log_format* parameter may be used for specifying log
format (see below).

.. note:: Access log is disabled by default.

Format specification.

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


Error logs
----------

*aiohttp.web* uses logger named ``'aiohttp.server'`` to store errors
given on web requests handling.

The log is always enabled.

To use different logger name please specify *logger* parameter
(:class:`logging.Logger` instance) onmake
:meth:`aiohttp.web.Application.make_handler` call.
