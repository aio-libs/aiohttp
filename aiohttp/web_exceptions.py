from .web_response import Response


__all__ = (
    'HTTPException',
    'HTTPError',
    'HTTPRedirection',
    'HTTPSuccessful',
    'HTTPOk',
    'HTTPCreated',
    'HTTPAccepted',
    'HTTPNonAuthoritativeInformation',
    'HTTPNoContent',
    'HTTPResetContent',
    'HTTPPartialContent',
    'HTTPMultipleChoices',
    'HTTPMovedPermanently',
    'HTTPFound',
    'HTTPSeeOther',
    'HTTPNotModified',
    'HTTPUseProxy',
    'HTTPTemporaryRedirect',
    'HTTPPermanentRedirect',
    'HTTPClientError',
    'HTTPBadRequest',
    'HTTPUnauthorized',
    'HTTPPaymentRequired',
    'HTTPForbidden',
    'HTTPNotFound',
    'HTTPMethodNotAllowed',
    'HTTPNotAcceptable',
    'HTTPProxyAuthenticationRequired',
    'HTTPRequestTimeout',
    'HTTPConflict',
    'HTTPGone',
    'HTTPLengthRequired',
    'HTTPPreconditionFailed',
    'HTTPRequestEntityTooLarge',
    'HTTPRequestURITooLong',
    'HTTPUnsupportedMediaType',
    'HTTPRequestRangeNotSatisfiable',
    'HTTPExpectationFailed',
    'HTTPMisdirectedRequest',
    'HTTPUnprocessableEntity',
    'HTTPFailedDependency',
    'HTTPUpgradeRequired',
    'HTTPPreconditionRequired',
    'HTTPTooManyRequests',
    'HTTPRequestHeaderFieldsTooLarge',
    'HTTPUnavailableForLegalReasons',
    'HTTPServerError',
    'HTTPInternalServerError',
    'HTTPNotImplemented',
    'HTTPBadGateway',
    'HTTPServiceUnavailable',
    'HTTPGatewayTimeout',
    'HTTPVersionNotSupported',
    'HTTPVariantAlsoNegotiates',
    'HTTPInsufficientStorage',
    'HTTPNotExtended',
    'HTTPNetworkAuthenticationRequired',
)


############################################################
# HTTP Exceptions
############################################################

class HTTPException(Exception):

    # You should set in subclasses:
    # status = 200

    status = None
    empty_body = False

    # backward compatibility
    @property
    def status_code(self):
        return self.status

    @status_code.setter
    def status_code(self, val):
        self.status = val

    def build_response(self):
        if self.status is None:
            raise RuntimeError("Cannot build abstract HTTP exception: "
                               "status is not set.")
        ret = Response(status=self.status)
        if not self.empty_body:
            ret.text = "{}: {}".format(self.status, self.reason)
        return ret


class HTTPError(HTTPException):
    """Base class for exceptions with status codes in the 400s and 500s."""


class HTTPRedirection(HTTPException):
    """Base class for exceptions with status codes in the 300s."""


class HTTPSuccessful(HTTPException):
    """Base class for exceptions with status codes in the 200s."""


class HTTPOk(HTTPSuccessful):
    status = 200


class HTTPCreated(HTTPSuccessful):
    status = 201


class HTTPAccepted(HTTPSuccessful):
    status = 202


class HTTPNonAuthoritativeInformation(HTTPSuccessful):
    status = 203


class HTTPNoContent(HTTPSuccessful):
    status = 204
    empty_body = True


class HTTPResetContent(HTTPSuccessful):
    status = 205
    empty_body = True


class HTTPPartialContent(HTTPSuccessful):
    status = 206


############################################################
# 3xx redirection
############################################################


class _HTTPMove(HTTPRedirection):

    def __init__(self, location):
        if not location:
            raise ValueError("HTTP redirects need a location to redirect to.")
        super().__init__()
        self.location = location

    def build_response(self):
        resp = super().build_response()
        resp.headers['Location'] = str(self.location)
        return resp


class HTTPMultipleChoices(_HTTPMove):
    status = 300


class HTTPMovedPermanently(_HTTPMove):
    status = 301


class HTTPFound(_HTTPMove):
    status = 302


# This one is safe after a POST (the redirected location will be
# retrieved with GET):
class HTTPSeeOther(_HTTPMove):
    status = 303


class HTTPNotModified(HTTPRedirection):
    # FIXME: this should include a date or etag header
    status = 304
    empty_body = True


class HTTPUseProxy(_HTTPMove):
    # Not a move, but looks a little like one
    status = 305


class HTTPTemporaryRedirect(_HTTPMove):
    status = 307


class HTTPPermanentRedirect(_HTTPMove):
    status = 308


############################################################
# 4xx client error
############################################################


class HTTPClientError(HTTPError):
    pass


class HTTPBadRequest(HTTPClientError):
    status = 400


class HTTPUnauthorized(HTTPClientError):
    status = 401


class HTTPPaymentRequired(HTTPClientError):
    status = 402


class HTTPForbidden(HTTPClientError):
    status = 403


class HTTPNotFound(HTTPClientError):
    status = 404


class HTTPMethodNotAllowed(HTTPClientError):
    status = 405

    def __init__(self, method, allowed_methods):
        super().__init__()
        self.allow = ','.join(sorted(allowed_methods))
        self.allowed_methods = allowed_methods
        self.method = method.upper()

    def build_response(self):
        resp = super().build_response()
        resp.headers['Allow'] = self.allow
        return resp


class HTTPNotAcceptable(HTTPClientError):
    status = 406


class HTTPProxyAuthenticationRequired(HTTPClientError):
    status = 407


class HTTPRequestTimeout(HTTPClientError):
    status = 408


class HTTPConflict(HTTPClientError):
    status = 409


class HTTPGone(HTTPClientError):
    status = 410


class HTTPLengthRequired(HTTPClientError):
    status = 411


class HTTPPreconditionFailed(HTTPClientError):
    status = 412


class HTTPRequestEntityTooLarge(HTTPClientError):
    status = 413


class HTTPRequestURITooLong(HTTPClientError):
    status = 414


class HTTPUnsupportedMediaType(HTTPClientError):
    status = 415


class HTTPRequestRangeNotSatisfiable(HTTPClientError):
    status = 416


class HTTPExpectationFailed(HTTPClientError):
    status = 417


class HTTPMisdirectedRequest(HTTPClientError):
    status = 421


class HTTPUnprocessableEntity(HTTPClientError):
    status = 422


class HTTPFailedDependency(HTTPClientError):
    status = 424


class HTTPUpgradeRequired(HTTPClientError):
    status = 426


class HTTPPreconditionRequired(HTTPClientError):
    status = 428


class HTTPTooManyRequests(HTTPClientError):
    status = 429


class HTTPRequestHeaderFieldsTooLarge(HTTPClientError):
    status = 431


class HTTPUnavailableForLegalReasons(HTTPClientError):
    status = 451

    def __init__(self, link):
        super().__init__()
        self.link = link

    def build_response(self):
        resp = super().build_response()
        resp.headers['Link'] = '<%s>; rel="blocked-by"' % self.link
        return resp


############################################################
# 5xx Server Error
############################################################
#  Response status codes beginning with the digit "5" indicate cases in
#  which the server is aware that it has erred or is incapable of
#  performing the request. Except when responding to a HEAD request, the
#  server SHOULD include an entity containing an explanation of the error
#  situation, and whether it is a temporary or permanent condition. User
#  agents SHOULD display any included entity to the user. These response
#  codes are applicable to any request method.


class HTTPServerError(HTTPError):
    pass


class HTTPInternalServerError(HTTPServerError):
    status = 500


class HTTPNotImplemented(HTTPServerError):
    status = 501


class HTTPBadGateway(HTTPServerError):
    status = 502


class HTTPServiceUnavailable(HTTPServerError):
    status = 503


class HTTPGatewayTimeout(HTTPServerError):
    status = 504


class HTTPVersionNotSupported(HTTPServerError):
    status = 505


class HTTPVariantAlsoNegotiates(HTTPServerError):
    status = 506


class HTTPInsufficientStorage(HTTPServerError):
    status = 507


class HTTPNotExtended(HTTPServerError):
    status = 510


class HTTPNetworkAuthenticationRequired(HTTPServerError):
    status = 511
