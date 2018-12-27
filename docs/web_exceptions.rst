.. _aiohttp-web-exceptions:

Web Server Exceptions
=====================

.. currentmodule:: aiohttp.web

Overview
--------

:mod:`aiohttp.web` defines a set of exceptions for every *HTTP status code*.

Each exception is a subclass of :exc:`HTTPException` and relates to a single
HTTP status code::

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

Classes :exc:`HTTPMultipleChoices`, :exc:`HTTPMovedPermanently`,
:exc:`HTTPFound`, :exc:`HTTPSeeOther`, :exc:`HTTPUseProxy`,
:exc:`HTTPTemporaryRedirect` have the following constructor signature::

    HTTPFound(location, *, headers=None, reason=None,
              body=None, text=None, content_type=None)

where *location* is value for *Location HTTP header*.

:exc:`HTTPMethodNotAllowed` is constructed by providing the incoming
unsupported method and list of allowed methods::

    HTTPMethodNotAllowed(method, allowed_methods, *,
                         headers=None, reason=None,
                         body=None, text=None, content_type=None)

Base HTTP Exception
-------------------

.. exception:: HTTPException(*, headers=None, reason=None, text=None, \
                             content_type=None)

   The base class for HTTP server exceptions. Inherited from :exc:`Exception`.

   :param headers: HTTP headers (:class:`~collections.abc.Mapping`)

   :param str reason: an optional custom HTTP reason. aiohttp uses *default reason
                      string* if not specified.

   :param str text: an optional text used in response body. If not specified *default
                    text* is constructed from status code and reason, e.g. `"404: Not
                    Found"`.

   :param str content_type: an optional Content-Type, `"text/plain"` by default.

   .. attribute:: status

      HTTP status code for the exception, :class:`int`

   .. attribute:: reason

      HTTP status reason for the exception, :class:`str`

   .. attribute:: text

      HTTP status reason for the exception, :class:`str` or ``None``
      for HTTP exceptions without body, e.g. "204 No Content"

   .. attribute:: headers

      HTTP headers for the exception, :class:`multidict.CIMultiDict`

   .. method:: make_response()

      Return a :class:`Response` object constructed from the exception. :attr:`status`,
      :attr:`reason`, :attr:`text` and :attr:`headers` response properties are
      initialized from the exception.


Successful Exceptions
---------------------

HTTP exceptions for status code in range 200-299. They are not *errors* but special
classes reflected in exceptions hierarchy. E.g. ``raise web.HTTPNoContent`` may look
strange a little but the construction is absolutely legal.

.. exception3:: HTTPSuccessful

   A base class for the category, a subclass of :exc:`HTTPException`.

.. exception:: HTTPOk

   An exception for *200 OK*, a subclass of :exc:`HTTPSuccessful`.

.. exception:: HTTPCreated

   An exception for *201 Created*, a subclass of :exc:`HTTPSuccessful`.

.. exception:: HTTPAccepted

   An exception for *202 Accepted*, a subclass of :exc:`HTTPSuccessful`.

.. exception:: HTTPNonAuthoritativeInformation

   An exception for *203 Non-Authoritative Information*, a subclass of
   :exc:`HTTPSuccessful`.

.. exception:: HTTPNoContent

   An exception for *204 No Content*, a subclass of :exc:`HTTPSuccessful`.

   Has no HTTP body.

.. exception:: HTTPResetContent

   An exception for *205 Reset Content*, a subclass of :exc:`HTTPSuccessful`.

   Has no HTTP body.

.. exception:: HTTPPartialContent

   An exception for *206 Partial Content*, a subclass of :exc:`HTTPSuccessful`.

Redirections
------------

HTTP exceptions for status code in range 300-399, e.g. ``raise
web.HTTPMovedPermanently(location='/new/path')``.

.. exception:: HTTPRedirection

   A base class for the category, a subclass of :exc:`HTTPException`.

.. exception:: HTTPMove(location, *, headers=None, reason=None, text=None, \
                        content_type=None)

   A base class for redirections with implied *Location* header,
   all redirections except :exc:`HTTPNotModified`.

   :param location: a :class:`yarl.URL` or :class:`str` used for *Location* HTTP
                    header.

   For other arguments see :exc:`HTTPException` constructor.

   .. attribute:: location

      A *Location* HTTP header value, :class:`yarl.URL`.

.. exception:: HTTPMultipleChoices

   An exception for *300 Multiple Choices*, a subclass of :exc:`HTTPMove`.

.. exception:: HTTPMovedPermanently

   An exception for *301 Moved Permanently*, a subclass of :exc:`HTTPMove`.

.. exception:: HTTPFound

   An exception for *302 Found*, a subclass of :exc:`HTTPMove`.

.. exception:: HTTPSeeOther

   An exception for *303 See Other*, a subclass of :exc:`HTTPMove`.

.. exception:: HTTPNotModified

   An exception for *304 Not Modified*, a subclass of :exc:`HTTPRedirection`.

   Has no HTTP body.

.. exception:: HTTPUseProxy

   An exception for *305 Use Proxy*, a subclass of :exc:`HTTPMove`.

.. exception:: HTTPTemporaryRedirect

   An exception for *307 Temporary Redirect*, a subclass of :exc:`HTTPMove`.

.. exception:: HTTPPermanentRedirect

   An exception for *308 Permanent Redirect*, a subclass of :exc:`HTTPMove`.


Client Errors
-------------

HTTP exceptions for status code in range 400-499, e.g. ``raise
web.HTTPNotFound()``.

.. exception:: HTTPClientError

   A base class for the category, a subclass of :exc:`HTTPException`.

.. exception:: HTTPBadRequest

   An exception for *400 Bad Request*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPUnauthorized

   An exception for *401 Unauthorized*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPPaymentRequired

   An exception for *402 Payment Required*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPForbidden

   An exception for *403 Forbidden*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPNotFound

   An exception for *404 Not Found*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPMethodNotAllowed(method, allowed_methods, *, \
                                    headers=None, reason=None, text=None, \
                                    content_type=None)

   An exception for *405 Method Not Allowed*, a subclass of
   :exc:`HTTPClientError`.

   :param str method: requested but not allowed HTTP method.

   :param allowed_methods: an iterable of allowed HTTP methods (:class:`str`),
                           *Allow* HTTP header is constracted from
                           the sequence separated by comma.

   For other arguments see :exc:`HTTPException` constructor.

   .. attribute:: allowed_methods

      A set of allowed HTTP methods.

   .. attribute:: method

      Requested but not allowed HTTP method.

.. exception:: HTTPNotAcceptable

   An exception for *406 Not Acceptable*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPProxyAuthenticationRequired

   An exception for *407 Proxy Authentication Required*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPRequestTimeout

   An exception for *408 Request Timeout*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPConflict

   An exception for *409 Conflict*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPGone

   An exception for *410 Gone*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPLengthRequired

   An exception for *411 Length Required*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPPreconditionFailed

   An exception for *412 Precondition Failed*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPLengthRequired

   An exception for *411 Length Required*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPLengthRequired

   An exception for *411 Length Required*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPLengthRequired

   An exception for *411 Length Required*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPLengthRequired

   An exception for *411 Length Required*, a subclass of :exc:`HTTPClientError`.
