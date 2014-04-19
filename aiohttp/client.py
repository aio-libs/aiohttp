"""HTTP Client for asyncio."""

__all__ = ['request', 'HttpClient']

import asyncio
import base64
import collections
import email.message
import http.client
import http.cookies
import json
import io
import inspect
import itertools
import logging
import mimetypes
import os
import random
import time
import uuid
import urllib.parse

import aiohttp

from requests.utils import requote_uri

@asyncio.coroutine
def request(method, url, *,
            params=None,
            data=None,
            headers=None,
            cookies=None,
            files=None,
            auth=None,
            allow_redirects=True,
            max_redirects=10,
            encoding='utf-8',
            version=(1, 1),
            timeout=None,
            compress=None,
            chunked=None,
            expect100=False,
            connector=None,
            loop=None,
            read_until_eof=True,
            request_class=None):
    """Constructs and sends a request. Returns response object.

    :param method: http method
    :param url: request url
    :param params: (optional) Dictionary or bytes to be sent in the query
      string of the new request
    :param data: (optional) Dictionary, bytes, or file-like object to
      send in the body of the request
    :param headers: (optional) Dictionary of HTTP Headers to send with
      the request
    :param cookies: (optional) Dict object to send with the request
    :param files: (optional) Dictionary of 'name': file-like-objects
       for multipart encoding upload
    :param auth: (optional) Auth tuple to enable Basic HTTP Auth
    :param timeout: (optional) Float describing the timeout of the request
    :param allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE
       redirect following is allowed.
    :param compress: Boolean. Set to True if request has to be compressed
       with deflate encoding.
    :param chunked: Boolean or Integer. Set to chunk size for chunked
       transfer encoding.
    :param expect100: Boolean. Expect 100-continue response from server.
    :param connector: aiohttp.conntect.SocketConnector instance to support
       connection pooling and session cookies.
    :param read_until_eof: Read response until eof if response
       does not have Content-Length header.
    :param request_class: Custom Request class implementation.
    :param loop: Optional event loop.

    Usage::

      >>> import aiohttp
      >>> resp = yield from aiohttp.request('GET', 'http://python.org/')
      >>> resp
      <HttpResponse(python.org/) [200]>
      >>> data = yield from resp.read_and_close()

    """
    redirects = 0
    if loop is None:
        loop = asyncio.get_event_loop()
    if request_class is None:
        request_class = HttpRequest
    if connector is None:
        connector = aiohttp.SocketConnector(loop=loop)

    while True:
        req = request_class(
            method, url, params=params, headers=headers, data=data,
            cookies=cookies, files=files, auth=auth, encoding=encoding,
            version=version, compress=compress, chunked=chunked,
            loop=loop, expect100=expect100)

        try:
            conn = yield from connector.connect(req)

            resp = req.send(conn.writer, conn.reader)
            try:
                if timeout:
                    yield from asyncio.wait_for(
                        resp.start(conn, read_until_eof), timeout, loop=loop)
                else:
                    yield from resp.start(conn, read_until_eof)
            except:
                resp.close()
                conn.close()
                raise
        except asyncio.TimeoutError:
            raise aiohttp.TimeoutError from None
        except aiohttp.BadStatusLine as exc:
            raise aiohttp.ClientConnectionError(exc)
        except OSError as exc:
            raise aiohttp.OsConnectionError(exc)

        # redirects
        if resp.status in (301, 302) and allow_redirects:
            redirects += 1
            if max_redirects and redirects >= max_redirects:
                resp.close()
                break

            r_url = resp.get('location') or resp.get('uri')

            scheme = urllib.parse.urlsplit(r_url)[0]
            if scheme not in ('http', 'https', ''):
                raise ValueError('Can redirect only to http or https')
            elif not scheme:
                r_url = urllib.parse.urljoin(url, r_url)

            url = urllib.parse.urldefrag(r_url)[0]
            if url:
                resp.close()
                continue

        break

    return resp


class HttpRequest:

    GET_METHODS = {'DELETE', 'GET', 'HEAD', 'OPTIONS'}
    POST_METHODS = {'PATCH', 'POST', 'PUT', 'TRACE'}
    ALL_METHODS = GET_METHODS.union(POST_METHODS)

    DEFAULT_HEADERS = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
    }

    body = b''
    auth = None
    response = None

    _writer = None  # async task for streaming data
    _continue = None  # waiter future for '100 Continue' response

    def __init__(self, method, url, *,
                 params=None, headers=None, data=None, cookies=None,
                 files=None, auth=None, encoding='utf-8', version=(1, 1),
                 compress=None, chunked=None, expect100=False,
                 verify_ssl=True, loop=None):
        self.url = url
        self.method = method.upper()
        self.encoding = encoding
        self.chunked = chunked
        self.compress = compress
        self.verify_ssl = verify_ssl
        self.loop = loop

        self.update_version(version)
        self.update_host(url)
        self.update_path(params, data)
        self.update_headers(headers)
        self.update_cookies(cookies)
        self.update_content_encoding()
        self.update_auth(auth)

        if data and not files:
            if self.method not in self.GET_METHODS:
                self.update_body_from_data(data)
        elif files:
            self.update_body_from_files(files, data)

        self.update_transfer_encoding()
        self.update_expect_continue(expect100)

    def __del__(self):
        """Close request on GC"""
        if self._writer is not None:
            self._writer.cancel()
            self._writer = None

    def update_host(self, url):
        """Update destination host, port and connection type (ssl)."""
        scheme, netloc, path, query, fragment = urllib.parse.urlsplit(url)
        if not netloc:
            raise ValueError('Host could not be detected.')

        # check domain idna encoding
        try:
            netloc = netloc.encode('idna').decode('utf-8')
        except UnicodeError:
            raise ValueError('URL has an invalid label.')

        # basic auth info
        if '@' in netloc:
            authinfo, netloc = netloc.split('@', 1)
            self.auth = authinfo.split(':', 1)
            if len(self.auth) == 1:
                self.auth.append('')

        # extract host and port
        self.ssl = scheme == 'https'
        if ':' in netloc:
            netloc, port_s = netloc.split(':', 1)
            try:
                self.port = int(port_s)
            except ValueError:
                raise ValueError(
                    'Port number could not be converted.') from None
        else:
            if self.ssl:
                self.port = http.client.HTTPS_PORT
            else:
                self.port = http.client.HTTP_PORT

        self.host = netloc

    def update_version(self, version):
        """Convert request version to two elements tuple.

        parser http version '1.1' => (1, 1)
        """
        if isinstance(version, str):
            v = [l.strip() for l in version.split('.', 1)]
            try:
                version = int(v[0]), int(v[1])
            except ValueError:
                raise ValueError(
                    'Can not parse http version number: {}'
                    .format(version)) from None
        self.version = version

    def update_path(self, params, data):
        """Build path."""
        # extract path
        scheme, netloc, path, query, fragment = urllib.parse.urlsplit(self.url)
        if not path:
            path = '/'

        if isinstance(params, dict):
            params = list(params.items())

        # for GET request include data to query params
        if data and self.method in self.GET_METHODS:
            if isinstance(data, dict):
                data = data.items()
            params = list(itertools.chain(params or (), data))

        if params:
            params = urllib.parse.urlencode(params)
            if query:
                query = '%s&%s' % (query, params)
            else:
                query = params

        self.path = urllib.parse.urlunsplit(
            ('', '', requote_uri(path), query, fragment))

    def update_headers(self, headers):
        """Update request headers."""
        self.headers = email.message.Message()
        if headers:
            if isinstance(headers, dict):
                headers = headers.items()

            for key, value in headers:
                self.headers.add_header(key, value)

        for hdr, val in self.DEFAULT_HEADERS.items():
            if hdr not in self.headers:
                self.headers[hdr] = val

        # add host
        if 'host' not in self.headers:
            self.headers['Host'] = self.host

    def update_cookies(self, cookies):
        """Update request cookies header."""
        if not cookies:
            return

        c = http.cookies.SimpleCookie()
        if 'cookie' in self.headers:
            c.load(self.headers.get('cookie', ''))
            del self.headers['cookie']

        if isinstance(cookies, dict):
            cookies = cookies.items()

        for name, value in cookies:
            if isinstance(value, http.cookies.Morsel):
                # use dict method because SimpleCookie class modifies value
                dict.__setitem__(c, name, value)
            else:
                c[name] = value

        self.headers['cookie'] = c.output(header='', sep=';').strip()

    def update_content_encoding(self):
        """Set request content encoding."""
        enc = self.headers.get('content-encoding', '').lower()
        if enc:
            self.compress = enc
            self.chunked = True  # enable chunked, no need to deal with length
        elif self.compress:
            if not isinstance(self.compress, str):
                self.compress = 'deflate'
            self.headers['content-encoding'] = self.compress
            self.chunked = True  # enable chunked, no need to deal with length

    def update_auth(self, auth):
        """Set basic auth."""
        if not auth:
            auth = self.auth

        if auth:
            if isinstance(auth, (tuple, list)) and len(auth) == 2:
                # basic auth
                self.headers['Authorization'] = 'Basic %s' % (
                    base64.b64encode(
                        ('%s:%s' % (auth[0], auth[1])).encode('latin1'))
                    .strip().decode('latin1'))
            else:
                raise ValueError("Only basic auth is supported")

    def update_body_from_data(self, data):
        if (hasattr(data, '__iter__') and not isinstance(
                data, (bytes, bytearray, str, list, dict))):
            self.body = data
            if 'content-length' not in self.headers and self.chunked is None:
                self.chunked = True
        else:
            if isinstance(data, (bytes, bytearray)):
                self.body = data
                if 'content-type' not in self.headers:
                    self.headers['content-type'] = 'application/octet-stream'
            else:
                # form data (x-www-form-urlencoded)
                if isinstance(data, dict):
                    data = list(data.items())

                if not isinstance(data, str):
                    data = urllib.parse.urlencode(data, doseq=True)

                self.body = data.encode(self.encoding)

                if 'content-type' not in self.headers:
                    self.headers['content-type'] = (
                        'application/x-www-form-urlencoded')

            if 'content-length' not in self.headers and not self.chunked:
                self.headers['content-length'] = str(len(self.body))

    def update_body_from_files(self, files, data):
        """Generate multipart/form-data body."""
        fields = []

        if data:
            if not isinstance(data, (list, dict)):
                raise NotImplementedError(
                    'Streamed body is not compatible with files.')

            if isinstance(data, dict):
                data = data.items()

            for field, val in data:
                fields.append((field, str_to_bytes(val)))

        if isinstance(files, dict):
            files = list(files.items())

        for rec in files:
            if not isinstance(rec, (tuple, list)):
                rec = (rec,)

            ft = None
            if len(rec) == 1:
                k = guess_filename(rec[0], 'unknown')
                fields.append((k, k, rec[0]))

            elif len(rec) == 2:
                k, fp = rec
                fn = guess_filename(fp, k)
                fields.append((k, fn, fp))

            else:
                k, fp, ft = rec
                fn = guess_filename(fp, k)
                fields.append((k, fn, fp, ft))

        self.chunked = self.chunked or 8192
        boundary = uuid.uuid4().hex

        self.body = encode_multipart_data(
            fields, bytes(boundary, 'latin1'))

        self.headers['content-type'] = (
            'multipart/form-data; boundary=%s' % boundary)

    def update_transfer_encoding(self):
        """Analyze transfer-encoding header."""
        te = self.headers.get('transfer-encoding', '').lower()

        if self.chunked:
            if 'content-length' in self.headers:
                del self.headers['content-length']
            if 'chunked' not in te:
                self.headers['transfer-encoding'] = 'chunked'

            self.chunked = self.chunked if type(self.chunked) is int else 8196
        else:
            if 'chunked' in te:
                self.chunked = 8196
            else:
                self.chunked = None
                if 'content-length' not in self.headers:
                    self.headers['content-length'] = str(len(self.body))

    def update_expect_continue(self, expect=False):
        if expect:
            self.headers['expect'] = '100-continue'
        elif self.headers.get('expect', '').lower() == '100-continue':
            expect = True

        if expect:
            self._continue = asyncio.Future(loop=self.loop)

    @asyncio.coroutine
    def write_bytes(self, request, reader):
        """Support coroutines that yields bytes objects."""
        # 100 response
        if self._continue is not None:
            yield from self._continue

        try:
            if inspect.isgenerator(self.body):
                exc = None
                value = None
                stream = self.body

                while True:
                    try:
                        if exc is not None:
                            result = stream.throw(exc)
                        else:
                            result = stream.send(value)
                    except StopIteration as exc:
                        if isinstance(exc.value, bytes):
                            yield from request.write(exc.value)
                        break
                    except:
                        self.response.close(True)
                        raise

                    if isinstance(result, asyncio.Future):
                        exc = None
                        value = None
                        try:
                            value = yield result
                        except Exception as err:
                            exc = err
                    elif isinstance(result, (bytes, bytearray)):
                        yield from request.write(result)
                        value = None
                    else:
                        raise ValueError(
                            'Bytes object is expected, got: %s.' %
                            type(result))
            else:
                if isinstance(self.body, bytes):
                    self.body = (self.body,)

                for chunk in self.body:
                    request.write(chunk)
        except Exception as exc:
            reader.set_exception(exc)
        else:
            request.write_eof()

        self._writer = None

    def send(self, writer, reader):
        request = aiohttp.Request(writer, self.method, self.path, self.version)

        if self.compress:
            request.add_compression_filter(self.compress)

        if self.chunked is not None:
            request.add_chunking_filter(self.chunked)

        request.add_headers(*self.headers.items())
        request.send_headers()

        self._writer = asyncio.async(
            self.write_bytes(request, reader), loop=self.loop)

        self.response = HttpResponse(
            self.method, self.path, self.host,
            writer=self._writer, continue100=self._continue)
        return self.response

    @asyncio.coroutine
    def close(self):
        if self._writer is not None:
            try:
                yield from self._writer
            finally:
                self._writer = None


class HttpResponse(http.client.HTTPMessage):

    message = None  # RawResponseMessage object

    # from the Status-Line of the response
    version = None  # HTTP-Version
    status = None   # Status-Code
    reason = None   # Reason-Phrase

    cookies = None  # Response cookies (Set-Cookie)
    content = None  # Payload stream

    _reader = None   # input stream
    _connection = None  # current connection
    _response_parser = aiohttp.HttpResponseParser()

    def __init__(self, method, url, host='', *, writer=None, continue100=None):
        super().__init__()

        self.method = method
        self.url = url
        self.host = host
        self._content = None
        self._writer = writer
        self._continue = continue100

    def __del__(self):
        if self._connection is not None:
            logging.warn('HttpResponse has to be closed explicitly! %s:%s:%s',
                         self.method, self.host, self.url)
            self.close(True)

    def __repr__(self):
        out = io.StringIO()
        print('<HttpResponse({}{}) [{} {}]>'.format(
            self.host, self.url, self.status, self.reason), file=out)
        print(super().__str__(), file=out)
        return out.getvalue()

    __str__ = __repr__

    def waiting_for_continue(self):
        return self._continue is not None

    def start(self, connection, read_until_eof=False):
        """Start response processing."""
        self._reader = connection.reader
        self._connection = connection

        while True:
            httpstream = self._reader.set_parser(self._response_parser)

            # read response
            self.message = yield from httpstream.read()
            if self.message.code != 100:
                break

            if self._continue is not None and not self._continue.done():
                self._continue.set_result(True)
                self._continue = None

        # response status
        self.version = self.message.version
        self.status = self.message.code
        self.reason = self.message.reason

        # headers
        for hdr, val in self.message.headers:
            self.add_header(hdr, val)

        # payload
        self.content = self._reader.set_parser(
            aiohttp.HttpPayloadParser(self.message, readall=read_until_eof))

        # cookies
        self.cookies = http.cookies.SimpleCookie()
        if 'Set-Cookie' in self:
            for hdr in self.get_all('Set-Cookie'):
                try:
                    self.cookies.load(hdr)
                except http.cookies.CookieError as exc:
                    logging.warn('Can not load response cookies: %s', exc)

        return self

    def close(self, force=False):
        if self._connection is not None:
            if force:
                self._connection.close()
            else:
                self._connection.release()
            self._connection = None
        if (self._writer is not None) and not self._writer.done():
            self._writer.cancel()
            self._writer = None

    @asyncio.coroutine
    def wait_for_close(self):
        if self._writer is not None:
            try:
                yield from self._writer
            finally:
                self._writer = None
        self.close()

    @asyncio.coroutine
    def read(self, decode=False):
        """Read response payload. Decode known types of content."""
        if self._content is None:
            buf = []
            total = 0
            try:
                while True:
                    chunk = yield from self.content.read()
                    size = len(chunk)
                    buf.append((chunk, size))
                    total += size
            except aiohttp.EofStream:
                pass

            self._content = bytearray(total)

            idx = 0
            content = memoryview(self._content)
            for chunk, size in buf:
                content[idx:idx+size] = chunk
                idx += size

        data = self._content

        if decode:
            ct = self.get('content-type', '').lower()
            if ct == 'application/json':
                data = json.loads(data.decode('utf-8'))

        return data

    @asyncio.coroutine
    def read_and_close(self, decode=False):
        """Read response payload and then close response."""
        try:
            payload = yield from self.read(decode)
            return payload
        finally:
            self.close()


def str_to_bytes(s, encoding='utf-8'):
    if isinstance(s, str):
        return s.encode(encoding)
    return s


def guess_filename(obj, default=None):
    name = getattr(obj, 'name', None)
    if name and name[0] != '<' and name[-1] != '>':
        return os.path.split(name)[-1]
    return default


def encode_multipart_data(fields, boundary, encoding='utf-8', chunk_size=8196):
    """
    Encode a list of fields using the multipart/form-data MIME format.

    fields:
        List of (name, value) or (name, filename, io) or
        (name, filename, io, MIME type) field tuples.
    """
    for rec in fields:
        yield b'--' + boundary + b'\r\n'

        field, *rec = rec

        if len(rec) == 1:
            data = rec[0]
            yield (('Content-Disposition: form-data; name="%s"\r\n\r\n' %
                    (field,)).encode(encoding))
            yield data + b'\r\n'

        else:
            if len(rec) == 3:
                fn, fp, ct = rec
            else:
                fn, fp = rec
                ct = (mimetypes.guess_type(fn)[0] or
                      'application/octet-stream')

            yield ('Content-Disposition: form-data; name="%s"; '
                   'filename="%s"\r\n' % (field, fn)).encode(encoding)
            yield ('Content-Type: %s\r\n\r\n' % (ct,)).encode(encoding)

            if isinstance(fp, str):
                fp = fp.encode(encoding)

            if isinstance(fp, bytes):
                fp = io.BytesIO(fp)

            while True:
                chunk = fp.read(chunk_size)
                if not chunk:
                    break
                yield str_to_bytes(chunk)

            yield b'\r\n'

    yield b'--' + boundary + b'--\r\n'


class HttpClient:
    """Allow to use mutiple hosts with same path. And automatically
    mark failed hosts.
    """

    def __init__(self, hosts, *, method=None, path=None,
                 ssl=False, timeout=None,
                 conn_pool=True, conn_timeout=None, failed_timeout=5.0,
                 resolve=True, resolve_timeout=360.0, verify_ssl=True,
                 loop=None):
        super().__init__()

        if isinstance(hosts, str):
            hosts = (hosts,)

        if not hosts:
            raise ValueError('Hosts are required')

        self._hosts = []
        for host in hosts:
            if isinstance(host, str):
                if ':' in host:
                    host, port = host.split(':')
                    try:
                        port = int(port)
                    except:
                        raise ValueError('Port has to be integer: %s' % host)
                else:
                    port = 80
            else:
                host, port = host

            self._hosts.append((host, port))

        self._method = method
        self._path = path
        self._timeout = timeout
        self._schema = 'https' if ssl else 'http'

        self._failed = collections.deque()
        self._failed_handle = None
        self._failed_timeout = failed_timeout

        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop

        if conn_pool:
            self._connector = aiohttp.SocketConnector(
                share_cookies=True, conn_timeout=conn_timeout,
                resolve=resolve, verify_ssl=verify_ssl, loop=loop)

            self._resolve_timeout = resolve_timeout
            self._resolve_handle = self._loop.call_later(
                self._resolve_timeout, self._cleanup_resolved_host)
        else:
            self._connector = None

    def _cleanup_resolved_host(self):
        if self._connector:
            self._connector.clear_resolved_hosts()
            self._resolve_handle.cancel()
            self._resolve_handle = self._loop.call_later(
                self._resolve_timeout, self._cleanup_resolved_host)

    def _resurrect_failed(self):
        now = int(time.time())

        while self._failed:
            if (now - self._failed[0][1]) >= self._failed_timeout:
                self._hosts.append(self._failed.popleft()[0])
            else:
                break

        if self._failed:
            self._failed_handle = self._loop.call_later(
                self._failed_timeout, self._resurrect_failed)
        else:
            self._failed_handle = None

    @asyncio.coroutine
    def request(self, method=None, path=None, *,
                params=None,
                data=None,
                headers=None,
                cookies=None,
                files=None,
                auth=None,
                allow_redirects=True,
                max_redirects=10,
                encoding='utf-8',
                version=(1, 1),
                compress=None,
                timeout=None,
                chunked=None,
                expect100=False,
                read_until_eof=True):

        if method is None:
            method = self._method
        if path is None:
            path = self._path
        if timeout is None:
            timeout = self._timeout

        # if all hosts marked as failed try first from failed
        if not self._hosts:
            self._hosts.append(self._failed.popleft()[0])

        hosts = self._hosts

        while hosts:
            idx = random.randint(0, len(hosts)-1)

            info = hosts[idx]
            url = urllib.parse.urljoin(
                '{}://{}:{}'.format(self._schema, info[0], info[1]), path)

            try:
                resp = yield from request(
                    method, url, params=params, data=data, headers=headers,
                    cookies=cookies, files=files, auth=auth,
                    encoding=encoding, allow_redirects=allow_redirects,
                    version=version, max_redirects=max_redirects,
                    timeout=timeout, compress=compress, chunked=chunked,
                    expect100=expect100, read_until_eof=read_until_eof,
                    connector=self._connector, loop=self._loop)
            except (aiohttp.ConnectionError, aiohttp.TimeoutError):
                pass
            else:
                if 500 <= resp.status <= 600:
                    self._cleanup_resolved_host()

                return resp

            if info in hosts:
                # could be removed concurrently
                hosts.remove(info)
                self._failed.append((info, int(time.time())))
                if not self._failed_handle:
                    self._failed_handle = self._loop.call_later(
                        self._failed_timeout, self._resurrect_failed)

                if self._connector:
                    self._connector.clear_resolved_hosts(info[0], info[1])

        raise aiohttp.ConnectionError('All hosts are unreachable.')
