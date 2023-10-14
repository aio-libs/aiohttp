.. currentmodule:: aiohttp.web

.. _aiohttp-web-exceptions:

Web Server Exceptions
=====================

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
         * 304 - HTTPNotModified
         HTTPMove
           * 300 - HTTPMultipleChoices
           * 301 - HTTPMovedPermanently
           * 302 - HTTPFound
           * 303 - HTTPSeeOther
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
                 text=None, content_type=None)

If not directly specified, *headers* will be added to the *default
response headers*.

Classes :exc:`HTTPMultipleChoices`, :exc:`HTTPMovedPermanently`,
:exc:`HTTPFound`, :exc:`HTTPSeeOther`, :exc:`HTTPUseProxy`,
:exc:`HTTPTemporaryRedirect` have the following constructor signature::

    HTTPFound(location, *,headers=None, reason=None,
              text=None, content_type=None)

where *location* is value for *Location HTTP header*.

:exc:`HTTPMethodNotAllowed` is constructed by providing the incoming
unsupported method and list of allowed methods::

    HTTPMethodNotAllowed(method, allowed_methods, *,
                         headers=None, reason=None,
                         text=None, content_type=None)

:exc:`HTTPUnavailableForLegalReasons` should be constructed with a ``link``
to yourself (as the entity implementing the blockage), and an explanation for
the block included in ``text``.::

    HTTPUnavailableForLegalReasons(link, *,
                                   headers=None, reason=None,
                                   text=None, content_type=None)

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

   .. attribute:: cookies

      An instance of :class:`http.cookies.SimpleCookie` for *outgoing* cookies.

      .. versionadded:: 4.0

   .. method:: set_cookie(name, value, *, path='/', expires=None, \
                          domain=None, max_age=None, \
                          secure=None, httponly=None, version=None, \
                          samesite=None)

      Convenient way for setting :attr:`cookies`, allows to specify
      some additional properties like *max_age* in a single call.

      .. versionadded:: 4.0

      :param str name: cookie name

      :param str value: cookie value (will be converted to
                        :class:`str` if value has another type).

      :param expires: expiration date (optional)

      :param str domain: cookie domain (optional)

      :param int max_age: defines the lifetime of the cookie, in
                          seconds.  The delta-seconds value is a
                          decimal non- negative integer.  After
                          delta-seconds seconds elapse, the client
                          should discard the cookie.  A value of zero
                          means the cookie should be discarded
                          immediately.  (optional)

      :param str path: specifies the subset of URLs to
                       which this cookie applies. (optional, ``'/'`` by default)

      :param bool secure: attribute (with no value) directs
                          the user agent to use only (unspecified)
                          secure means to contact the origin server
                          whenever it sends back this cookie.
                          The user agent (possibly under the user's
                          control) may determine what level of
                          security it considers appropriate for
                          "secure" cookies.  The *secure* should be
                          considered security advice from the server
                          to the user agent, indicating that it is in
                          the session's interest to protect the cookie
                          contents. (optional)

      :param bool httponly: ``True`` if the cookie HTTP only (optional)

      :param int version: a decimal integer, identifies to which
                          version of the state management
                          specification the cookie
                          conforms. (Optional, *version=1* by default)

      :param str samesite: Asserts that a cookie must not be sent with
         cross-origin requests, providing some protection
         against cross-site request forgery attacks.
         Generally the value should be one of: ``None``,
         ``Lax`` or ``Strict``. (optional)

      .. warning::

         In HTTP version 1.1, ``expires`` was deprecated and replaced with
         the easier-to-use ``max-age``, but Internet Explorer (IE6, IE7,
         and IE8) **does not** support ``max-age``.

   .. method:: del_cookie(name, *, path='/', domain=None)

      Deletes cookie.

      .. versionadded:: 4.0

      :param str name: cookie name

      :param str domain: optional cookie domain

      :param str path: optional cookie path, ``'/'`` by default


Successful Exceptions
---------------------

HTTP exceptions for status code in range 200-299. They are not *errors* but special
classes reflected in exceptions hierarchy. E.g. ``raise web.HTTPNoContent`` may look
strange a little but the construction is absolutely legal.

.. exception:: HTTPSuccessful

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

HTTP exceptions for status code in range 400-499, e.g. ``raise web.HTTPNotFound()``.

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
                           *Allow* HTTP header is constructed from
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

.. exception:: HTTPRequestEntityTooLarge(max_size, actual_size, **kwargs)

   An exception for *413 Entity Too Large*, a subclass of :exc:`HTTPClientError`.

   :param int max_size: Maximum allowed request body size

   :param int actual_size: Actual received size

   For other acceptable parameters see :exc:`HTTPException` constructor.

.. exception:: HTTPRequestURITooLong

   An exception for *414 URI is too long*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPUnsupportedMediaType

   An exception for *415 Entity body in unsupported format*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPRequestRangeNotSatisfiable

   An exception for *416 Cannot satisfy request range*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPExpectationFailed

   An exception for *417 Expect condition could not be satisfied*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPMisdirectedRequest

   An exception for *421 Misdirected Request*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPUnprocessableEntity

   An exception for *422 Unprocessable Entity*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPFailedDependency

   An exception for *424 Failed Dependency*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPUpgradeRequired

   An exception for *426 Upgrade Required*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPPreconditionRequired

   An exception for *428 Precondition Required*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPTooManyRequests

   An exception for *429 Too Many Requests*, a subclass of :exc:`HTTPClientError`.

.. exception:: HTTPRequestHeaderFieldsTooLarge

   An exception for *431 Requests Header Fields Too Large*, a subclass of
   :exc:`HTTPClientError`.

.. exception:: HTTPUnavailableForLegalReasons(link, *, \
                                              headers=None, \
                                              reason=None, \
                                              text=None, \
                                              content_type=None)


   An exception for *451 Unavailable For Legal Reasons*, a subclass of
   :exc:`HTTPClientError`.

   :param link: A link to yourself (as the entity implementing the blockage),
                :class:`str`, :class:`~yarl.URL` or ``None``.

   For other parameters see :exc:`HTTPException` constructor.
   A reason for the block should be included in ``text``.

   .. attribute:: link

      A :class:`~yarl.URL` link to the entity implementing the blockage or ``None``,
      read-only property.


Server Errors
-------------

HTTP exceptions for status code in range 500-599, e.g. ``raise web.HTTPBadGateway()``.


.. exception:: HTTPServerError

   A base class for the category, a subclass of :exc:`HTTPException`.

.. exception:: HTTPInternalServerError

   An exception for *500 Server got itself in trouble*, a subclass of
   :exc:`HTTPServerError`.

.. exception:: HTTPNotImplemented

   An exception for *501 Server does not support this operation*, a subclass of
   :exc:`HTTPServerError`.

.. exception:: HTTPBadGateway

   An exception for *502 Invalid responses from another server/proxy*, a
   subclass of :exc:`HTTPServerError`.

.. exception:: HTTPServiceUnavailable

   An exception for *503 The server cannot process the request due to a high
   load*, a subclass of :exc:`HTTPServerError`.

.. exception:: HTTPGatewayTimeout

   An exception for *504 The gateway server did not receive a timely response*,
   a subclass of :exc:`HTTPServerError`.

.. exception:: HTTPVersionNotSupported

   An exception for *505 Cannot fulfill request*, a subclass of :exc:`HTTPServerError`.

.. exception:: HTTPVariantAlsoNegotiates

   An exception for *506 Variant Also Negotiates*, a subclass of :exc:`HTTPServerError`.

.. exception:: HTTPInsufficientStorage

   An exception for *507 Insufficient Storage*, a subclass of :exc:`HTTPServerError`.

.. exception:: HTTPNotExtended

   An exception for *510 Not Extended*, a subclass of :exc:`HTTPServerError`.

.. exception:: HTTPNetworkAuthenticationRequired

   An exception for *511 Network Authentication Required*, a subclass of
   :exc:`HTTPServerError`.
