.. currentmodule:: aiohttp

.. _aiohttp-multipart:

Working with Multipart
======================

``aiohttp`` supports a full featured multipart reader and writer. Both
are designed with streaming processing in mind to avoid unwanted
footprint which may be significant if you're dealing with large
payloads, but this also means that most I/O operation are only
possible to be executed a single time.

Reading Multipart Responses
---------------------------

Assume you made a request, as usual, and want to process the response multipart
data::

    async with aiohttp.request(...) as resp:
        pass

First, you need to wrap the response with a
:meth:`MultipartReader.from_response`. This needs to keep the implementation of
:class:`MultipartReader` separated from the response and the connection routines
which makes it more portable::

    reader = aiohttp.MultipartReader.from_response(resp)

Let's assume with this response you'd received some JSON document and multiple
files for it, but you don't need all of them, just a specific one.

So first you need to enter into a loop where the multipart body will
be processed::

    metadata = None
    filedata = None
    while True:
        part = await reader.next()

The returned type depends on what the next part is: if it's a simple body part
then you'll get :class:`BodyPartReader` instance here, otherwise, it will
be another :class:`MultipartReader` instance for the nested multipart. Remember,
that multipart format is recursive and supports multiple levels of nested body
parts. When there are no more parts left to fetch, ``None`` value will be
returned - that's the signal to break the loop::

    if part is None:
        break

Both :class:`BodyPartReader` and :class:`MultipartReader` provides access to
body part headers: this allows you to filter parts by their attributes::

    if part.headers[aiohttp.hdrs.CONTENT_TYPE] == 'application/json':
        metadata = await part.json()
        continue

Neither :class:`BodyPartReader` nor :class:`MultipartReader` instances
read the whole body part data without explicitly asking for.
:class:`BodyPartReader` provides a set of helpers methods
to fetch popular content types in friendly way:

- :meth:`BodyPartReader.text` for plain text data;
- :meth:`BodyPartReader.json` for JSON;
- :meth:`BodyPartReader.form` for `application/www-urlform-encode`

Each of these methods automatically recognizes if content is compressed by
using `gzip` and `deflate` encoding (while it respects `identity` one), or if
transfer encoding is base64 or `quoted-printable` - in each case the result
will get automatically decoded. But in case you need to access to raw binary
data as it is, there are :meth:`BodyPartReader.read` and
:meth:`BodyPartReader.read_chunk` coroutine methods as well to read raw binary
data as it is all-in-single-shot or by chunks respectively.

When you have to deal with multipart files, the :attr:`BodyPartReader.filename`
property comes to help. It's a very smart helper which handles
`Content-Disposition` handler right and extracts the right filename attribute
from it::

    if part.filename != 'secret.txt':
        continue

If current body part does not matches your expectation and you want to skip it
- just continue a loop to start a next iteration of it. Here is where magic
happens. Before fetching the next body part ``await reader.next()`` it
ensures that the previous one was read completely. If it was not, all its content
sends to the void in term to fetch the next part. So you don't have to care
about cleanup routines while you're within a loop.

Once you'd found a part for the file you'd searched for, just read it. Let's
handle it as it is without applying any decoding magic::

    filedata = await part.read(decode=False)

Later you may decide to decode the data. It's still simple and possible
to do::

    filedata = part.decode(filedata)

Once you are done with multipart processing, just break a loop::

    break


Sending Multipart Requests
--------------------------

:class:`MultipartWriter` provides an interface to build multipart payload from
the Python data and serialize it into chunked binary stream. Since multipart
format is recursive and supports deeply nesting, you can use ``with`` statement
to design your multipart data closer to how it will be::

    with aiohttp.MultipartWriter('mixed') as mpwriter:
        ...
        with aiohttp.MultipartWriter('related') as subwriter:
            ...
        mpwriter.append(subwriter)

        with aiohttp.MultipartWriter('related') as subwriter:
            ...
            with aiohttp.MultipartWriter('related') as subsubwriter:
                ...
            subwriter.append(subsubwriter)
        mpwriter.append(subwriter)

        with aiohttp.MultipartWriter('related') as subwriter:
            ...
        mpwriter.append(subwriter)

The :meth:`MultipartWriter.append` is used to join new body parts into a
single stream. It accepts various inputs and determines what default headers
should be used for.

For text data default `Content-Type` is :mimetype:`text/plain; charset=utf-8`::

    mpwriter.append('hello')

For binary data :mimetype:`application/octet-stream` is used::

    mpwriter.append(b'aiohttp')

You can always override these default by passing your own headers with
the second argument::

    mpwriter.append(io.BytesIO(b'GIF89a...'),
                    {'CONTENT-TYPE': 'image/gif'})

For file objects `Content-Type` will be determined by using Python's
mod:`mimetypes` module and additionally `Content-Disposition` header
will include the file's basename::

    part = root.append(open(__file__, 'rb'))

If you want to send a file with a different name, just handle the
:class:`~aiohttp.payload.Payload` instance which :meth:`MultipartWriter.append` will
always return and set `Content-Disposition` explicitly by using
the :meth:`Payload.set_content_disposition() <aiohttp.payload.Payload.set_content_disposition>` helper::

    part.set_content_disposition('attachment', filename='secret.txt')

Additionally, you may want to set other headers here::

    part.headers[aiohttp.hdrs.CONTENT_ID] = 'X-12345'

If you'd set `Content-Encoding`, it will be automatically applied to the
data on serialization (see below)::

    part.headers[aiohttp.hdrs.CONTENT_ENCODING] = 'gzip'

There are also :meth:`MultipartWriter.append_json` and
:meth:`MultipartWriter.append_form` helpers which are useful to work with JSON
and form urlencoded data, so you don't have to encode it every time manually::

    mpwriter.append_json({'test': 'passed'})
    mpwriter.append_form([('key', 'value')])

When it's done, to make a request just pass a root :class:`MultipartWriter`
instance as :meth:`aiohttp.ClientSession.request` ``data`` argument::

    await session.post('http://example.com', data=mpwriter)

Behind the scenes :meth:`MultipartWriter.write` will yield chunks of every
part and if body part has `Content-Encoding` or `Content-Transfer-Encoding`
they will be applied on streaming content.

Please note, that on :meth:`MultipartWriter.write` all the file objects
will be read until the end and there is no way to repeat a request without
rewinding their pointers to the start.

Example MJPEG Streaming ``multipart/x-mixed-replace``. By default
:meth:`MultipartWriter.write` appends closing ``--boundary--`` and breaks your
content. Providing `close_boundary = False` prevents this.::

    my_boundary = 'some-boundary'
    response = web.StreamResponse(
        status=200,
        reason='OK',
        headers={
            'Content-Type': 'multipart/x-mixed-replace;boundary={}'.format(my_boundary)
        }
    )
    while True:
        frame = get_jpeg_frame()
        with MultipartWriter('image/jpeg', boundary=my_boundary) as mpwriter:
            mpwriter.append(frame, {
                'Content-Type': 'image/jpeg'
            })
            await mpwriter.write(response, close_boundary=False)
        await response.drain()

Hacking Multipart
-----------------

The Internet is full of terror and sometimes you may find a server which
implements multipart support in strange ways when an oblivious solution
does not work.

For instance, is server used :class:`cgi.FieldStorage` then you have
to ensure that no body part contains a `Content-Length` header::

    for part in mpwriter:
        part.headers.pop(aiohttp.hdrs.CONTENT_LENGTH, None)

On the other hand, some server may require to specify `Content-Length` for the
whole multipart request. `aiohttp` does not do that since it sends multipart
using chunked transfer encoding by default. To overcome this issue, you have
to serialize a :class:`MultipartWriter` by our own in the way to calculate its
size::

    class Writer:
        def __init__(self):
            self.buffer = bytearray()

        async def write(self, data):
            self.buffer.extend(data)

    writer = Writer()
    await mpwriter.write(writer)
    await aiohttp.post('http://example.com',
                       data=writer.buffer, headers=mpwriter.headers)

Sometimes the server response may not be well formed: it may or may not
contains nested parts. For instance, we request a resource which returns
JSON documents with the files attached to it. If the document has any
attachments, they are returned as a nested multipart.
If it has not it responds as plain body parts:

.. code-block:: none

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

Reading such kind of data in single stream is possible, but is not clean at
all::

    result = []
    while True:
        part = await reader.next()

        if part is None:
            break

        if isinstance(part, aiohttp.MultipartReader):
            # Fetching files
            while True:
                filepart = await part.next()
                if filepart is None:
                    break
                result[-1].append((await filepart.read()))

        else:
            # Fetching document
            result.append([(await part.json())])

Let's hack a reader in the way to return pairs of document and reader of the
related files on each iteration::

    class PairsMultipartReader(aiohttp.MultipartReader):

        # keep reference on the original reader
        multipart_reader_cls = aiohttp.MultipartReader

        async def next(self):
            """Emits a tuple of document object (:class:`dict`) and multipart
            reader of the followed attachments (if any).

            :rtype: tuple
            """
            reader = await super().next()

            if self._at_eof:
                return None, None

            if isinstance(reader, self.multipart_reader_cls):
                part = await reader.next()
                doc = await part.json()
            else:
                doc = await reader.json()

            return doc, reader

And this gives us a more cleaner solution::

    reader = PairsMultipartReader.from_response(resp)
    result = []
    while True:
        doc, files_reader = await reader.next()

        if doc is None:
            break

        files = []
        while True:
            filepart = await files_reader.next()
            if file.part is None:
                break
            files.append((await filepart.read()))

        result.append((doc, files))

.. seealso:: :ref:`aiohttp-multipart-reference`
