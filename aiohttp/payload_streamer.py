""" Payload implemenation for coroutines as data provider.

As a simple case, you can upload data from file::

   @aiohttp.streamer
   def file_sender(writer, file_name=None):
      with open(file_name, 'rb') as f:
          chunk = f.read(2**16)
          while chunk:
              yield from writer.write(chunk)

              chunk = f.read(2**16)

Then you can use `file_sender` like this:

    async with session.post('http://httpbin.org/post',
                            data=file_sender(file_name='hude_file')) as resp:
        print(await resp.text())

..note:: Coroutine must accept `writer` as first argument

"""

import asyncio

from . import payload

__all__ = ('streamer',)


class _stream_wrapper:

    def __init__(self, coro, args, kwargs):
        self.coro = coro
        self.args = args
        self.kwargs = kwargs

    @asyncio.coroutine
    def __call__(self, writer):
        yield from self.coro(writer, *self.args, **self.kwargs)


class streamer:

    def __init__(self, coro):
        self.coro = coro

    def __call__(self, *args, **kwargs):
        return _stream_wrapper(self.coro, args, kwargs)


class StreamWrapperPayload(payload.Payload):

    @asyncio.coroutine
    def write(self, writer):
        yield from self._value(writer)


class StreamPayload(StreamWrapperPayload):

    def __init__(self, value, *args, **kwargs):
        super().__init__(value(), *args, **kwargs)

    @asyncio.coroutine
    def write(self, writer):
        yield from self._value(writer)


payload.PAYLOAD_REGISTRY.register(StreamPayload, streamer)
payload.PAYLOAD_REGISTRY.register(StreamWrapperPayload, _stream_wrapper)
