import io
import json

import aiohttp
import aiohttp.hdrs as h


class Stream(object):

    def __init__(self, content):
        self.content = io.BytesIO(content)

    async def read(self, size=None):
        return self.content.read(size)

    async def readline(self):
        return self.content.readline()


async def test_async_for_reader(loop):
    data = [{"test": "passed"}, 42, b'plain text', b'aiohttp\n']
    reader = aiohttp.MultipartReader(
        headers={h.CONTENT_TYPE: 'multipart/mixed; boundary=":"'},
        content=Stream(b'\r\n'.join([
            b'--:',
            b'Content-Type: application/json',
            b'',
            json.dumps(data[0]).encode(),
            b'--:',
            b'Content-Type: application/json',
            b'',
            json.dumps(data[1]).encode(),
            b'--:',
            b'Content-Type: multipart/related; boundary="::"',
            b'',
            b'--::',
            b'Content-Type: text/plain',
            b'',
            data[2],
            b'--::',
            b'Content-Disposition: attachment; filename="aiohttp"',
            b'Content-Type: text/plain',
            b'Content-Length: 28',
            b'Content-Encoding: gzip',
            b'',
            b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03K\xcc\xcc\xcf())'
            b'\xe0\x02\x00\xd6\x90\xe2O\x08\x00\x00\x00',
            b'--::--',
            b'--:--',
            b''])))
    idata = iter(data)
    async for part in reader:
        if isinstance(part, aiohttp.BodyPartReader):
            assert next(idata) == (await part.json())
        else:
            async for subpart in part:
                assert next(idata) == await subpart.read(decode=True)


async def test_async_for_bodypart(loop):
    part = aiohttp.BodyPartReader(
        boundary=b'--:',
        headers={},
        content=Stream(b'foobarbaz\r\n--:--'))
    async for data in part:
        assert data == b'foobarbaz'
