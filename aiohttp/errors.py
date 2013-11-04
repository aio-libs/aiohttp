"""http related errors."""

__all__ = ['HttpException', 'HttpErrorException', 'BadRequestException',
           'IncompleteRead', 'BadStatusLine', 'LineTooLong', 'InvalidHeader',
           'ConnectionError', 'TimeoutError']

import http.client
from asyncio import TimeoutError


class ConnectionError(Exception):
    """http connection error"""


class HttpException(http.client.HTTPException):

    code = None
    headers = ()
    message = ''


class HttpErrorException(HttpException):

    def __init__(self, code, message='', headers=None):
        self.code = code
        self.headers = headers
        self.message = message


class BadRequestException(HttpException):

    code = 400
    message = 'Bad Request'


class IncompleteRead(BadRequestException, http.client.IncompleteRead):
    pass


class BadStatusLine(BadRequestException, http.client.BadStatusLine):
    pass


class LineTooLong(BadRequestException, http.client.LineTooLong):
    pass


class InvalidHeader(BadRequestException):

    def __init__(self, hdr):
        super().__init__('Invalid HTTP Header: {}'.format(hdr))
        self.hdr = hdr
