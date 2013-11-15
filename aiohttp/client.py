"""HTTP Client for asyncio."""

__all__ = ['request', 'HttpClient']

import asyncio
import base64
import collections
import email.message
import functools
import http.client
import http.cookies
import json
import io
import inspect
import itertools
import mimetypes
import os
import random
import ssl
import socket
import time
import uuid
import urllib.parse

import aiohttp


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
            conn_timeout=None,
            compress=None,
            chunked=None,
            expect100=False,
            session=None,
            verify_ssl=True,
            connection_params=None,
            loop=None):
    """Constructs and sends a request. Returns response object.

    method: http method
    url: request url
    params: (optional) Dictionary or bytes to be sent in the query string
      of the new request
    data: (optional) Dictionary, bytes, or file-like object to
      send in the body of the request
    headers: (optional) Dictionary of HTTP Headers to send with the request
    cookies: (optional) Dict object to send with the request
    files: (optional) Dictionary of 'name': file-like-objects
       for multipart encoding upload
    auth: (optional) Auth tuple to enable Basic HTTP Auth
    timeout: (optional) Float describing the timeout of the request
    conn_timeout: (optional) Float describing the timeout
       of the host connection
    allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE
       redirect following is allowed.
    compress: Boolean. Set to True if request has to be compressed
       with deflate encoding.
    chunked: Boolean or Integer. Set to chunk size for chunked
       transfer encoding.
    expect100: Boolean. Expect 100-continue response from server.
    session: aiohttp.Session instance to support connection pooling and
       session cookies.
    loop: Optional event loop.

    Usage:

      import aiohttp
      >> resp = yield from aiohttp.request('GET', 'http://python.org/')
      >> resp
      <HttpResponse(python.org/) [200]>

      >> data = yield from resp.read()

    """
    redirects = 0
    if loop is None:
        loop = asyncio.get_event_loop()

    while True:
        req = HttpRequest(
            method, url, params=params, headers=headers, data=data,
            cookies=cookies, files=files, auth=auth, encoding=encoding,
            version=version, compress=compress, chunked=chunked,
            verify_ssl=verify_ssl, loop=loop, expect100=expect100)

        if session is None:
            conn = _connect(req, loop, connection_params)
        else:
            conn = session.start(req, loop, connection_params)

        if conn_timeout is None and timeout is not None:
            conn_timeout = timeout

        conn_task = asyncio.async(conn, loop=loop)
        try:
            if conn_timeout:
                transport, proto, wrp = yield from asyncio.wait_for(
                    conn_task, conn_timeout, loop=loop)
            else:
                transport, proto, wrp = yield from conn_task

            resp = yield from _make_request(
                transport, proto, req, wrp, timeout, loop)
        except asyncio.TimeoutError:
            raise aiohttp.TimeoutError from None
        except OSError as exc:
            raise aiohttp.ConnectionError(exc)
        finally:
            conn_task.cancel()

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


@asyncio.coroutine
def _connect(req, loop, params):
    if params is not None:
        transport, proto = yield from loop.create_connection(
            functools.partial(aiohttp.StreamProtocol, loop=loop),
            params['host'], params['port'],
            ssl=params['ssl'], family=params['family'],
            proto=params['proto'], flags=params['flags'])
    else:
        transport, proto = yield from loop.create_connection(
            functools.partial(aiohttp.StreamProtocol, loop=loop),
            req.host, req.port, ssl=req.ssl)
    wrp = TransportWrapper(transport)
    return transport, proto, wrp


@asyncio.coroutine
def _make_request(transport, proto, req, wrapper, timeout, loop):
    try:
        resp = req.send(transport)
        if timeout:
            yield from asyncio.wait_for(
                resp.start(proto, wrapper), timeout, loop=loop)
        else:
            yield from resp.start(proto, wrapper)
    except:
        transport.close()
        raise
    else:
        return resp


class TransportWrapper:

    def __init__(self, transport):
        self.transport = transport

    def close(self, force=False):
        self.transport.close()


class HttpClient:
    """Allow to use mutiple hosts with same path. And automatically
    mark failed hosts.
    """

    _resolve_timeout = 360.0  # update dns info every 5 minutes

    def __init__(self, hosts, *,
                 method=None, path=None, ssl=False, session=False,
                 timeout=None, conn_timeout=None, failed_timeout=5.0,
                 resolve=True, loop=None):
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
        self._ssl = ssl
        self._timeout = timeout
        self._conn_timeout = conn_timeout
        self._schema = 'https' if ssl else 'http'
        self._session = aiohttp.Session() if session else None

        self._failed = collections.deque()
        self._failed_handle = None
        self._failed_timeout = failed_timeout

        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop

        self._resolve = resolve
        self._resolved_hosts = {}
        if resolve:
            self._resolve_handle = self._loop.call_later(
                self._resolve_timeout, self._cleanup_resolved_host)

    def _cleanup_resolved_host(self):
        self._resolved_hosts.clear()
        self._resolve_handle = self._loop.call_later(
            self._resolve_timeout, self._cleanup_resolved_host)

    @asyncio.coroutine
    def _resolve_host(self, host, port):
        if self._resolve:
            key = (host, port)
            if key not in self._resolved_hosts:
                infos = yield from self._loop.getaddrinfo(
                    host, port, type=socket.SOCK_STREAM)

                hosts = []
                for family, _, proto, _, address in infos:
                    hosts.append(
                        {'host': host, 'port': port,
                         'ssl': self._ssl, 'family': family,
                         'proto': proto, 'flags': socket.AI_NUMERICHOST})
                self._resolved_hosts[key] = hosts

            return self._resolved_hosts[key]
        else:
            return [{'host': host, 'port': port,
                     'ssl': self._ssl, 'family': 0, 'proto': 0, 'flags': 0}]

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
                conn_timeout=None,
                chunked=None,
                expect100=False,
                verify_ssl=True):

        if method is None:
            method = self._method
        if path is None:
            path = self._path
        if timeout is None:
            timeout = self._timeout
        if conn_timeout is None:
            conn_timeout = self._conn_timeout

        # if all hosts marked as failed try first from failed
        if not self._hosts:
            self._hosts.append(self._failed.popleft()[0])

        hosts = self._hosts

        while hosts:
            idx = random.randint(0, len(hosts)-1)

            h_info = hosts[idx]
            url = urllib.parse.urljoin(
                '{}://{}:{}'.format(
                    self._schema, h_info[0], h_info[1]), path)
            host_params = yield from self._resolve_host(h_info[0], h_info[1])

            for conn_params in host_params:
                try:
                    resp = yield from request(
                        method, url, params=params, data=data, headers=headers,
                        cookies=cookies, files=files, auth=auth,
                        encoding=encoding, allow_redirects=allow_redirects,
                        version=version, max_redirects=max_redirects,
                        conn_timeout=conn_timeout, timeout=timeout,
                        compress=compress, chunked=chunked,
                        verify_ssl=verify_ssl, expect100=expect100,
                        session=self._session, connection_params=conn_params,
                        loop=self._loop)
                except (aiohttp.ConnectionError, aiohttp.TimeoutError):
                    pass
                else:
                    return resp

            if h_info in hosts:
                # could be removed concurrently
                hosts.remove(h_info)
                self._failed.append((h_info, int(time.time())))
                if not self._failed_handle:
                    self._failed_handle = self._loop.call_later(
                        self._failed_timeout, self._resurrect_failed)

                key = (h_info[0], h_info[1])
                if key in self._resolved_hosts:
                    del self._resolved_hosts[key]

        raise aiohttp.ConnectionError('All hosts are unreachable.')


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
        if self.ssl and not self.verify_ssl:
            sslcontext = self.ssl = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslcontext.options |= ssl.OP_NO_SSLv2
            sslcontext.set_default_verify_paths()

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
        else:
            path = urllib.parse.unquote(path)

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
            ('', '', urllib.parse.quote(path), query, fragment))

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
    def write_bytes(self, request, is_stream):
        """Support coroutines that yields bytes objects."""
        # 100 response
        if self._continue is not None:
            yield from self._continue

        if is_stream:
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
                        request.write(exc.value)
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
                elif isinstance(result, bytes):
                    request.write(result)
                    value = None
                else:
                    raise ValueError(
                        'Bytes object is expected, got: %s.' % type(result))
        else:
            if isinstance(self.body, bytes):
                self.body = (self.body,)

            for chunk in self.body:
                request.write(chunk)

        request.write_eof()
        self._writer = None

    def send(self, transport):
        request = aiohttp.Request(
            transport, self.method, self.path, self.version)

        if self.compress:
            request.add_compression_filter(self.compress)

        if self.chunked is not None:
            request.add_chunking_filter(self.chunked)

        request.add_headers(*self.headers.items())
        request.send_headers()

        is_stream = inspect.isgenerator(self.body)

        if is_stream or self._continue is not None:
            self._writer = asyncio.async(
                self.write_bytes(request, is_stream), loop=self.loop)
        else:
            if isinstance(self.body, bytes):
                self.body = (self.body,)

            for chunk in self.body:
                request.write(chunk)

            request.write_eof()

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

    content = None  # payload stream
    stream = None   # input stream
    transport = None  # current transport

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
        self.close()

    def __repr__(self):
        out = io.StringIO()
        print('<HttpResponse({}{}) [{} {}]>'.format(
            self.host, self.url, self.status, self.reason), file=out)
        print(super().__str__(), file=out)
        return out.getvalue()

    def start(self, stream, transport):
        """Start response processing."""
        self.stream = stream
        self.transport = transport

        while True:
            httpstream = stream.set_parser(self._response_parser)

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
        self.content = stream.set_parser(
            aiohttp.HttpPayloadParser(self.message))

        # cookies
        self.cookies = http.cookies.SimpleCookie()
        if 'Set-Cookie' in self:
            for hdr in self.get_all('Set-Cookie'):
                self.cookies.load(hdr)

        return self

    def close(self, force=False):
        if self.transport is not None:
            self.transport.close(force)
            self.transport = None
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
