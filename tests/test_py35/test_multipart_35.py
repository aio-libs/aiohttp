import io
import json

import aiohttp
import aiohttp.hdrs as h


class Stream(object):

    def __init__(self, content):
        self.content = io.BytesIO(content)

    async def read(self, size=None):
        return self.content.read(size)

    def at_eof(self):
        return self.content.tell() == len(self.content.getbuffer())

    async def readline(self):
        return self.content.readline()

    def unread_data(self, data):
        self.content = io.BytesIO(data + self.content.read())


async def test_async_for_reader(loop):
    data = [
        {"test": "passed"},
        42,
        b'plain text',
        b'aiohttp\n',
        b'no epilogue']
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
            b'--::',
            b'Content-Type: multipart/related; boundary=":::"',
            b'',
            b'--:::',
            b'Content-Type: text/plain',
            b'',
            data[4],
            b'--:::--',
            b'--::--',
            b'',
            b'--:--',
            b''])))
    idata = iter(data)

    async def check(reader):
        async for part in reader:
            if isinstance(part, aiohttp.BodyPartReader):
                if part.headers[h.CONTENT_TYPE] == 'application/json':
                    assert next(idata) == (await part.json())
                else:
                    assert next(idata) == await part.read(decode=True)
            else:
                await check(part)

    await check(reader)


async def test_async_for_bodypart(loop):
    part = aiohttp.BodyPartReader(
        boundary=b'--:',
        headers={},
        content=Stream(b'foobarbaz\r\n--:--'))
    async for data in part:
        assert data == b'foobarbaz'
