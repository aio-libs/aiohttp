.. highlight:: python

.. module:: aiohttp.multipart

.. _aiohttp-multipart:

Working with Multipart
======================

`aiohttp` supports full featured multipart reader and writer. Both are designed
with steaming processing in mind to avoid unwanted footprint which may be
significant if you're dealing with large payloads, but this also means that
most I/O operation are only possible to execute only a single time.

Reading Multipart Responses
---------------------------

Assume you made a request, as usual, and want to process the respond multipart
data::

    >>> resp = yield from aiohttp.request(...)

First, you need to wrap the response with a
:meth:`MultipartReader.from_response`. This needs to keep implementation of
:class:`MultipartReader` separated from response and connection routines what
makes him more portable::

    >>> reader = aiohttp.MultipartReader.from_response(resp)

Let's assume with this response you'd received some JSON document and multiple
files for it, but you don't need all of them, just a specific one.

So first you need to enter into a loop where multipart body will be processed::

    >>> metadata = None
    >>> filedata = None
    >>> while True:
    ...     part = yield from reader.next()

The returned type depends on what the next part is: if it's a simple body part
than you'll get :class:`BodyPartReader` instance here, otherwise, it will
be another :class:`MultipartReader` instance for the nested multipart. Remember,
that multipart format is recursive and supports multiple levels of nested body
parts. When there are no more parts left to fetch, ``None`` value will be
returned - that's our signal to break the loop::

    ...     if part is None:
    ...         break

Both :class:`BodyPartReader` and :class:`MultipartReader` provides access to
body part headers: this allows you to filter parts by their attributes::

    ...     if part.headers[aiohttp.hdrs.CONTENT-TYPE] == 'application/json':
    ...         metadata = yield from part.json()
    ...         continue

Nor :class:`BodyPartReader` or :class:`MultipartReader` instances doesn't
reads whole body part data without explicit asking for. :class:`BodyPartReader`
provides a set of helpers to fetch popular content types in friendly way:

- :meth:`BodyPartReader.text` for plaintext data;
- :meth:`BodyPartReader.json` for JSON;
- :meth:`BodyPartReader.form` for `application/www-urlform-encode`

Each of these helpers automagically recognizes if content is compressed by
using `gzip` and `deflate` encoding (while it respects `identity` one), or if
transfer encoding is base64 or `quoted-printable` - in each case the result
will get automagically decoded. But in case if you need to access to raw binary
data as it is, there are :meth:`BodyPartReader.read` and
:meth:`BodyPartReader.read_chunk` coroutine methods as well to read raw binary
data as it is all-in-single-shot or by chunks respectively.

When you have to deal with multipart files, the :attr:`BodyPartReader.filename`
property comes to the aid. It's very smart helper which handles
`Content-Disposition` handler right and extracts the right filename attribute
from it::

    ...     if part.filename != 'secret.txt':
    ...         continue

If current body part doesn't matches your expectation and you want to skip it
- just continue a loop to start a next iteration of it. Here the magic happens.
Before fetch next body part ``yield from reader.next()`` ensures that previous
one was read completely. If it wasn't even started to be, all it content
sends to the void in term to fetch the next part. So you don't have to care
about cleanup routines while you're within a loop.

Once you'd found a part for the file you'd searched for, just read it. Let's
handle it as it is without applying any decoding magic::

    ...     filedata = yield from part.read(decode=False)

Later you may decide to decode the data. It's still simple and possible
to do::

    ...     filedata = part.decode(filedata)

Once you done multipart processing, just break a loop::

    ...     break

And release connection to not let it hold a response in the middle of the data::

    ...  yield from resp.release()  # or yield from reader.release()


Sending Multipart Requests
--------------------------

:class:`MultipartWriter` provides an interface to build multipart payload from
the Python data and serialize it into chunked binary stream. Since multipart
format is recursive and supports deeply nestings, you can use ``with`` statement
to design your multipart data closer to how it will be::

    >>> with aiohttp.MultipartWriter('mixed') as mpwriter:
    ...     ...
    ...     with aiohttp.MultipartWriter('related') as subwriter:
    ...         ...
    ...     mpwriter.append(subwriter)
    ...
    ...     with aiohttp.MultipartWriter('related') as subwriter:
    ...         ...
    ...         with aiohttp.MultipartWriter('related') as subsubwriter:
    ...             ...
    ...         subwriter.append(subsubwriter)
    ...     mpwriter.append(subwriter)
    ...
    ...     with aiohttp.MultipartWriter('related') as subwriter:
    ...         ...
    ...     mpwriter.append(subwriter)

The :meth:`MultipartWriter.append` is used join a new body parts into the
single stream. It accepts various input and determines which default headers
should be used for.

For text data default `Content-Type` is :mimetype:`text/plain; charset=utf-8`::

    ...     mpwriter.append('hello')

For binary data :mimetype:`application/octet-stream` is used::

    ...     mpwriter.append(b'aiohttp')

You can always override these default by passing own headers with the second
argument::

    ...     mpwriter.append(io.BytesIO(b'GIF89a...'),
                            {'CONTENT-TYPE': 'image/gif'})

For file objects `Content-Type` will be determined by using Python's
`mimetypes`_ module and additionally `Content-Disposition` header will include
file's basename::

    ...     part = root.append(open(__file__, 'rb))

If you want to send a file with different name, just handle the
:class:`BodyPartWriter` instance which :meth:`MultipartWriter.append` always
returns and set `Content-Disposition` explicitly by using
:meth:`BodyPartWriter.set_content_disposition` helper::

    ...     part.set_content_disposition('attachment', filename='secret.txt')

Additionally, you may set other headers here::

    ...     part.headers[aiohttp.hdrs.CONTENT_ID] = 'X-12345'

If you'd set `Content-Encoding`, it will be automatically applied to the
data on serialization (see below)::

    ...     part.headers[aiohttp.hdrs.CONTENT_ENCODING] = 'gzip'

There are also :meth:`MultipartWriter.append_json` and
:meth:`MultipartWriter.append_form` helpers which are useful to work with JSON
and form urlencoded data, so you don't have to encode it every time manually::

    ...     mpwriter.append_json({'test': 'passed'})
    ...     mpwriter.append_form([('key', 'value')])

When it's done, to make a request just pass root :class:`MultipartWriter`
instance as :func:`aiohttp.client.request` `data` argument::

    >>> yield from aiohttp.request('POST', 'http://example.com', data=mpwriter)

Behind the scene :meth:`MultipartWriter.serialize` will yield by chunks every
part and if body part has `Content-Encoding` or `Content-Transfer-Encoding`
they will be applied on streaming content.

Please note, that on :meth:`MultipartWriter.serialize` all the file objects
will be read till the end and there is no way to repeat a request without rewind
their pointers to the start.

Hacking Multipart
-----------------

The Internet is a full of terror and sometimes you may find a server which
implements a multipart support in a strange ways when an oblivious solution
doesn't works.

For instance, is server used `cgi.FieldStorage`_ then you have to ensure that
no body part contains a `Content-Length` header::

    for part in mpwriter:
        part.headers.pop(aiohttp.hdrs.CONTENT_LENGTH, None)

On the other hand, some server may require to specify `Content-Length` for the
whole multipart request. `aiohttp` doesn't do that since it sends multipart
using chunked transfer encoding by default. To overcome this issue, you have
to serialize a :class:`MultipartWriter` by our own in the way to calculate it
size::

    body = b''.join(mpwriter.serialize())
    yield from aiohttp.request('POST', 'http://example.com',
                               data=body, headers=mpwriter.headers)

Sometimes the server response may not be well structured: it may or may not
contains nested parts. For instance, we requesting a resource which returns
JSON documents with the files attached to it. If document has any attachments,
they are returned as a nested multipart thing. If it has not it comes as plain
body part::

    CONTENT-TYPE: multipart/mixed; boundary=--:

    --:
    CONTENT-TYPE: application/json

    {"_id": "foo"}
    --:
    CONTENT-TYPE: multipart/related; boundary=----:

    ----:
    CONTENT-TYPE: application/json

    {"_id": "bar"}
    ----:
    CONTENT-TYPE: text/plain
    CONTENT-DISPOSITION: attachment; filename=bar.txt

    bar! bar! bar!
    ----:--
    --:
    CONTENT-TYPE: application/json

    {"_id": "boo"}
    --:
    CONTENT-TYPE: multipart/related; boundary=----:

    ----:
    CONTENT-TYPE: application/json

    {"_id": "baz"}
    ----:
    CONTENT-TYPE: text/plain
    CONTENT-DISPOSITION: attachment; filename=baz.txt

    baz! baz! baz!
    ----:--
    --:--

Reading such kind of data in single stream is possible, but not clean a lot::

    result = []
    while True:
        part = yield from reader.next()

        if part is None:
            break

        if isinstance(part, aiohttp.MultipartReader):
            # Fetching files
            while True:
                filepart = yield from part.next()
                if filepart is None:
                    break
                result[-1].append((yield from filepart.read()))

        else:
            # Fetching document
            result.append([(yield from part.json())])

Let's hack a reader in the way to return pairs of document and reader of the
related files on each iteration::

    class PairsMultipartReader(aiohttp.MultipartReader):

        # keep reference on the original reader
        multipart_reader_cls = aiohttp.MultipartReader

        @asyncio.coroutine
        def next(self):
            """Emits a tuple of document object (:class:`dict`) and multipart
            reader of the followed attachments (if any).

            :rtype: tuple
            """
            reader = yield from super().next()

            if self._at_eof:
                return None, None

            if isinstance(reader, self.multipart_reader_cls):
                part = yield from reader.next()
                doc = yield from part.json()
            else:
                doc = yield from reader.json()

            return doc, reader

And this gives us a more cleaner solution::

    reader = PairsMultipartReader.from_response(resp)
    result = []
    while True:
        doc, files_reader = yield from reader.next()

        if doc is None:
            break

        files = []
        while True:
            filepart = yield from files_reader.next()
            if file.part is None:
                break
            files.append((yield from filepart.read()))

        result.append((doc, files))

.. seealso:: Multipart API in :ref:`aiohttp-api` section.


.. _cgi.FieldStorage: https://docs.python.org/3.4/library/cgi.html
.. _mimetypes: https://docs.python.org/3.4/library/mimetypes.html
