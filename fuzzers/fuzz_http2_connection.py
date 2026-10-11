#!/usr/bin/python3

# Copyright 2022-2025 Google LLC, 2026 aio-libs contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import struct
import sys
from contextlib import suppress

import atheris  # noqa: I900

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from hpack import Encoder
    from yarl import URL

    from aiohttp.http_exceptions import ContentEncodingError
    from aiohttp.http2.connection import Http2Connection, Http2Protocol
    from aiohttp.http2.errors import ProtocolError
    from aiohttp.http2.stream import Stream, StreamState

def _drain_future(fut) -> None:
    """Mark a future's exception as retrieved (suppresses asyncio warnings)."""
    if fut is None:
        return
    try:
        if fut.done() and not fut.cancelled():
            fut.exception()
    except BaseException:
        pass


def _drain_stream(stream: "Stream") -> None:
    """Retrieve any exceptions queued on a stream's futures."""
    _drain_future(stream.response_future)

    # body_reader.set_exception(...) forwards to the internal waiter when a
    # read() is in flight. Grab it if it still exists.
    reader = stream.body_reader
    _drain_future(getattr(reader, "_waiter", None))

    # Drop the stored exception so StreamReader.read() doesn't re-raise it
    # into a future we never observe.
    if getattr(reader, "_exception", None) is not None:
        reader._exception = None


def _drain_connection(conn: "Http2Connection") -> None:
    for fut in list(conn._pending_streams):
        _drain_future(fut)
    for stream in list(conn.streams.values()):
        _drain_stream(stream)


# HTTP/2 frame types
FRAME_DATA = 0
FRAME_HEADERS = 1
FRAME_RST_STREAM = 3
FRAME_SETTINGS = 4
FRAME_PING = 6
FRAME_GOAWAY = 7
FRAME_WINDOW_UPDATE = 8

# HTTP/2 flags
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4


class MockTransport:
    """Minimal transport that records writes and tracks close state."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def get_extra_info(self, name: str, default=None):
        return default


def make_frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Build a single HTTP/2 frame."""
    length = len(payload)
    return (
        struct.pack("!I", length)[1:]          # 24-bit length
        + bytes([ftype, flags])                # type + flags
        + struct.pack("!I", stream_id)         # 32-bit stream id
        + payload
    )


@atheris.instrument_func  # type: ignore[attr-defined]
async def fuzz_http2_async(data: bytes) -> None:  # type: ignore[misc]
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]

    loop = asyncio.get_running_loop()
    protocol = Http2Protocol(loop)

    transport = MockTransport()
    conn = Http2Connection(transport, loop, protocol)
    conn.initiate_connection()

    # Separate HPACK encoder to simulate the server side.
    server_encoder = Encoder()
    streams: list[Stream] = []

    async def wait_or_none(coro, timeout: float = 0.01):
        try:
            return await asyncio.wait_for(coro, timeout)
        except (
            ConnectionError,
            ProtocolError,
            RuntimeError,
            KeyError,
            ContentEncodingError,
        ):
            return None

    try:
        for _ in range(fdp.ConsumeIntInRange(0, 50)):
            lower_bound = 0
            # we don't want a large queue of 
            # pending streams
            if conn._pending_streams:
                lower_bound = 1
            op = fdp.ConsumeIntInRange(lower_bound, 12)

            # 0: create a new client stream
            if op == 0:
                if len(conn.streams) >= conn.max_concurrent_streams:
                    conn._pending_streams.append(conn._loop.create_future())
                else:
                    stream = await wait_or_none(conn.create_stream())
                    if stream is not None:
                        streams.append(stream)

            # 1: send HEADERS on an existing stream
            elif op == 1 and streams:
                stream = fdp.PickValueInList(streams)
                if stream.stream_id not in conn.streams:
                    continue

                url = URL(f"http://example.com/{fdp.ConsumeIntInRange(0, 100_000)}")
                headers = [
                    (
                        fdp.ConsumeUnicodeNoSurrogates(10),
                        fdp.ConsumeUnicodeNoSurrogates(20),
                    )
                    for _ in range(fdp.ConsumeIntInRange(0, 5))
                ]

                with suppress(ConnectionError, ProtocolError, RuntimeError, ValueError):
                    conn.send_headers(
                        stream.stream_id,
                        fdp.PickValueInList(["GET", "POST", "PUT", "DELETE"]),
                        url,
                        headers,
                        end_stream=fdp.ConsumeBool(),
                    )

            # 2: send DATA on an existing stream
            elif op == 2 and streams:
                stream = fdp.PickValueInList(streams)
                if stream.stream_id not in conn.streams:
                    continue

                # NOTE we need a way to verify that send_data doesn't hang
                # if an exception (e.g., connection error) is raised
                upper = min(conn.session_outbound_window, stream.outbound_window)
                if upper <= 0:
                    continue
                payload = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, upper))
                result = await wait_or_none(
                    conn.send_data(stream.stream_id, payload, fdp.ConsumeBool())
                )

            # 3: feed a server DATA frame
            elif op == 3:
                sid = (
                    fdp.PickValueInList([s.stream_id for s in streams])
                    if streams and fdp.ConsumeBool()
                    else (fdp.ConsumeIntInRange(1, 100) | 1)
                )
                payload = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1024))
                flags = FLAG_END_STREAM if fdp.ConsumeBool() else 0
                conn.data_received(make_frame(FRAME_DATA, flags, sid, payload))

            # 4: feed a server HEADERS frame
            elif op == 4:
                sid = (
                    fdp.PickValueInList([s.stream_id for s in streams])
                    if streams and fdp.ConsumeBool()
                    else (fdp.ConsumeIntInRange(1, 100) | 1)
                )

                headers = [(":status", str(fdp.ConsumeIntInRange(100, 599)))]
                for _ in range(fdp.ConsumeIntInRange(0, 5)):
                    headers.append(
                        (
                            fdp.ConsumeUnicodeNoSurrogates(10),
                            fdp.ConsumeUnicodeNoSurrogates(20),
                        )
                    )

                try:
                    payload = server_encoder.encode(headers)
                except Exception:
                    continue

                flags = FLAG_END_HEADERS
                if fdp.ConsumeBool():
                    flags |= FLAG_END_STREAM

                conn.data_received(make_frame(FRAME_HEADERS, flags, sid, payload))

            # 5: feed a server SETTINGS frame
            elif op == 5:
                pairs = []
                for _ in range(fdp.ConsumeIntInRange(0, 5)):
                    setting = fdp.ConsumeIntInRange(1, 6)
                    value = fdp.ConsumeIntInRange(0, 2**20)
                    pairs.append(struct.pack("!H I", setting, value))

                payload = b"".join(pairs)
                conn.data_received(make_frame(FRAME_SETTINGS, 0, 0, payload))

            # 6: feed WINDOW_UPDATE
            elif op == 6:
                sid = 0
                if streams and fdp.ConsumeBool():
                    sid = fdp.PickValueInList([s.stream_id for s in streams])

                inc = fdp.ConsumeIntInRange(1, 65535)
                conn.data_received(
                    make_frame(FRAME_WINDOW_UPDATE, 0, sid, struct.pack("!I", inc))
                )

            # 7: feed RST_STREAM
            elif op == 7:
                if not streams:
                    continue
                sid = fdp.PickValueInList([s.stream_id for s in streams])
                err = fdp.ConsumeIntInRange(0, 20)
                conn.data_received(
                    make_frame(FRAME_RST_STREAM, 0, sid, struct.pack("!I", err))
                )

            # 8: feed GOAWAY
            elif op == 8:
                last = fdp.ConsumeIntInRange(0, 2**31 - 1)
                err = fdp.ConsumeIntInRange(0, 20)
                conn.data_received(
                    make_frame(FRAME_GOAWAY, 0, 0, struct.pack("!I I", last, err))
                )

            # 9: feed PING
            elif op == 9:
                payload = fdp.ConsumeBytes(8).ljust(8, b"\0")
                conn.data_received(make_frame(FRAME_PING, 0, 0, payload))

            # 10: read from a stream body
            elif op == 10 and streams:
                stream = fdp.PickValueInList(streams)
                await wait_or_none(
                    stream.body_reader.read(fdp.ConsumeIntInRange(1, 1024)),
                    timeout=0.02,
                )

            # 11: force a stream state transition
            elif op == 11 and streams:
                stream = fdp.PickValueInList(streams)
                new_state = fdp.PickValueInList(list(StreamState))
                with suppress(ProtocolError):
                    stream.transition(new_state)

            # 12: close the connection
            elif op == 12:
                conn.close()

            # Drain anything that got an exception during this iteration.
            _drain_connection(conn)

    finally:
        # Cancel remaining work, then drain every future we created.
        for stream in streams:
            with suppress(BaseException):
                stream.cancel(ConnectionError("fuzz end"))
            _drain_stream(stream)

        for fut in list(conn._pending_streams):
            _drain_future(fut)
            if not fut.done():
                fut.cancel()
        conn._pending_streams.clear()

        for stream in list(conn.streams.values()):
            _drain_stream(stream)

        with suppress(Exception):
            conn.close()

@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:  # type: ignore[misc]
    asyncio.run(fuzz_http2_async(data))


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)  # type: ignore[attr-defined]
    atheris.Fuzz()  # type: ignore[attr-defined]
