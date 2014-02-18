"""http related errors."""

__all__ = ['HttpException', 'HttpErrorException', 'BadRequestException',
           'HttpBadRequest', 'HttpMethodNotAllowed',
           'IncompleteRead', 'BadStatusLine', 'LineTooLong', 'InvalidHeader',
           'ConnectionError', 'OsConnectionError', 'ClientConnectionError',
           'TimeoutError']

import http.client
from asyncio import TimeoutError


class ConnectionError(Exception):
    """http connection error"""


class OsConnectionError(ConnectionError):
    """OSError error"""


class ClientConnectionError(ConnectionError):
    """BadStatusLine error """


class HttpException(http.client.HTTPException):

    code = None
    headers = ()
    message = ''


class HttpErrorException(HttpException):

    def __init__(self, code, message='', headers=None):
        self.code = code
        self.headers = headers
        self.message = message


class HttpBadRequest(HttpException):

    code = 400
    message = 'Bad Request'


BadRequestException = HttpBadRequest


class HttpMethodNotAllowed(HttpException):

    code = 405
    message = 'Method Not Allowed'


class IncompleteRead(HttpBadRequest, http.client.IncompleteRead):
    pass


class BadStatusLine(HttpBadRequest, http.client.BadStatusLine):
    pass


class LineTooLong(HttpBadRequest, http.client.LineTooLong):
    pass


class InvalidHeader(HttpBadRequest):

    def __init__(self, hdr):
        super().__init__('Invalid HTTP Header: {}'.format(hdr))
        self.hdr = hdr
