"""HTTP/2 Server"""

import asyncio

import h2.connection
import h2.events

import aiohttp.errors
import aiohttp.hdrs
import aiohttp.helpers
import aiohttp.protocol
import aiohttp.protocol2
import aiohttp.server
import aiohttp.streams

from multidict import CIMultiDict


class ServerHTTP2Protocol(aiohttp.server.ServerHttpProtocol):
    """
    A class that implements ServerHTTPProtocol for HTTP/2 servers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._streams = {}
        self._conn = None

    @asyncio.coroutine
    def start(self):
        """
        Start processing incoming requests.

        Unlike in the case of ServerHTTPProtocol, this loop can repeatedly
        handle many requests in parallel.
        """
        conn = self._conn = h2.connection.H2Connection(
            client_side=False, header_encoding=None
        )
        conn.initiate_connection()

        eventstream = self.reader.set_parser(
            aiohttp.protocol2.HTTP2Parser(conn)
        )

        while True:
            try:
                events = yield from eventstream.read()
            except aiohttp.errors.ClientDisconnectedError:
                # Unclean termination, but only a problem if streams are open.
                # TODO: check that there are none.
                break

            # TODO: Refactor the event handlers to be multiple methods.
            # TODO: Flow control.
            # TODO: Priority.
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    hdrs = CIMultiDict(
                        (
                            k.decode('utf-8', 'surrogateescape'),
                            v.decode('utf-8', 'surrogateescape'),
                        )
                        for k, v in event.headers
                    )
                    # These pops need to be capitalised, because of
                    # https://github.com/aio-libs/multidict/issues/1
                    host = hdrs.pop(':AUTHORITY')
                    hdrs.pop(':SCHEME')
                    hdrs[aiohttp.hdrs.HOST] = host

                    # TODO: This isn't quite right, but it's close enough
                    # for now.
                    encoding = hdrs.get('content-encoding', None)
                    content_length = hdrs.get('content-length', 0)

                    msg = aiohttp.protocol.RawRequestMessage(
                        method=hdrs.pop(':METHOD'),
                        path=hdrs.pop(':PATH'),
                        version=aiohttp.protocol2.HttpVersion20,
                        headers=hdrs,
                        raw_headers=event.headers,
                        should_close=False,
                        compression=encoding,
                    )
                    if content_length:
                        reader = aiohttp.streams.StreamReader(loop=self._loop)
                    else:
                        reader = aiohttp.server.EMPTY_PAYLOAD

                    self._streams[event.stream_id] = reader

                    # Dispatch the handler
                    aiohttp.helpers.ensure_future(
                        self.handle_request(msg, reader, event.stream_id)
                    )
                elif isinstance(event, h2.events.DataReceived):
                    reader = self._streams[event.stream_id]
                    reader.feed_data(event.data)
                elif isinstance(event, h2.events.StreamEnded):
                    reader = self._streams.pop(event.stream_id)
                    reader.feed_eof()
                elif isinstance(event, h2.events.StreamReset):
                    try:
                        reader = self._streams.pop(event.stream_id)
                    except KeyError:
                        pass
                    else:
                        reader.feed_eof()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    # TODO: Logging of errors is good.
                    break

            data = conn.data_to_send()
            if data:
                self.transport.write(data)
