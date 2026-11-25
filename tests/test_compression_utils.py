"""Tests for compression utils."""

import gzip
import os
import sys
import zlib
from collections.abc import Callable
from typing import Any, cast

import pytest

from aiohttp.compression_utils import (
    MAX_DECOMPRESS_MEMBERS,
    MEMBER_COST,
    MEMBER_WINDOW_MAX,
    MEMBER_WINDOW_MIN,
    TooManyMembersError,
    ZLibBackend,
    ZLibCompressor,
    ZLibDecompressObjProtocol,
    ZLibDecompressor,
    ZSTDDecompressor,
)

try:
    if sys.version_info >= (3, 14):
        import compression.zstd as zstandard  # noqa: I900
    else:
        import backports.zstd as zstandard
except ImportError:  # pragma: no cover
    zstandard = None  # type: ignore[assignment]


class _RecordingDecompressObj:
    """decompressobj proxy recording the size of every buffer fed to it."""

    def __init__(self, obj: ZLibDecompressObjProtocol, feeds: list[int]) -> None:
        self._obj = obj
        self._feeds = feeds

    def __getattr__(self, name: str) -> Any:
        return getattr(self._obj, name)

    def decompress(self, data: Any, max_length: int = 0) -> bytes:
        self._feeds.append(len(data))
        return self._obj.decompress(data, max_length)


def _gzip_member(size: int) -> bytes:
    """Return a gzip member of exactly ``size`` bytes."""
    co = zlib.compressobj(0, wbits=31)
    # Stored, so 10 bytes of header, 5 of block header, the data, 8 of trailer.
    member = co.compress(os.urandom(size - 23)) + co.flush()
    assert len(member) == size
    return member


def _members_accepted(d: ZLibDecompressor | ZSTDDecompressor, member: bytes) -> int:
    """Feed ``member`` a call at a time until refused, returning how many decoded."""
    accepted = 0
    with pytest.raises(TooManyMembersError):
        for _ in range(10 * MAX_DECOMPRESS_MEMBERS):
            d.decompress_sync(member)
            accepted += 1
    return accepted


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_compression_round_trip_in_executor() -> None:
    """Ensure that compression and decompression work correctly in the executor."""
    compressor = ZLibCompressor(
        strategy=ZLibBackend.Z_DEFAULT_STRATEGY, max_sync_chunk_size=1
    )
    assert type(compressor._compressor) is type(ZLibBackend.compressobj())
    decompressor = ZLibDecompressor(max_sync_chunk_size=1)
    assert type(decompressor._decompressor) is type(ZLibBackend.decompressobj())
    data = b"Hi" * 100
    compressed_data = await compressor.compress(data) + compressor.flush()
    decompressed_data = await decompressor.decompress(compressed_data)
    assert data == decompressed_data


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_compression_round_trip_in_event_loop() -> None:
    """Ensure that compression and decompression work correctly in the event loop."""
    compressor = ZLibCompressor(
        strategy=ZLibBackend.Z_DEFAULT_STRATEGY, max_sync_chunk_size=10000
    )
    assert type(compressor._compressor) is type(ZLibBackend.compressobj())
    decompressor = ZLibDecompressor(max_sync_chunk_size=10000)
    assert type(decompressor._decompressor) is type(ZLibBackend.decompressobj())
    data = b"Hi" * 100
    compressed_data = await compressor.compress(data) + compressor.flush()
    decompressed_data = await decompressor.decompress(compressed_data)
    assert data == decompressed_data


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_unlimited() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    result = d.decompress_sync(frame1 + frame2)
    assert result == b"AAAABBBB"


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_max_length_partial() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    result = d.decompress_sync(frame1 + frame2, max_length=6)
    assert result == b"AAAABB"


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_max_length_exhausted() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    result = d.decompress_sync(frame1 + frame2, max_length=4)
    assert result == b"AAAA"


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_multi_frame_max_length_exhausted_preserves_unused_data() -> None:
    d = ZSTDDecompressor()
    frame1 = zstandard.compress(b"AAAA")
    frame2 = zstandard.compress(b"BBBB")
    frame3 = zstandard.compress(b"CCCC")
    result1 = d.decompress_sync(frame1 + frame2, max_length=4)
    assert result1 == b"AAAA"
    result2 = d.decompress_sync(frame3)
    assert result2 == b"BBBBCCCC"


def test_zlib_gzip_multi_member_unlimited() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    result = d.decompress_sync(member1 + member2)
    assert result == b"AAAABBBB"


def test_zlib_gzip_multi_member_max_length_partial() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    result = d.decompress_sync(member1 + member2, max_length=6)
    assert result == b"AAAABB"


def test_zlib_gzip_multi_member_max_length_exhausted() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    result = d.decompress_sync(member1 + member2, max_length=4)
    assert result == b"AAAA"


def test_zlib_gzip_multi_member_max_length_exhausted_preserves_unused_data() -> None:
    d = ZLibDecompressor(encoding="gzip")
    member1 = gzip.compress(b"AAAA")
    member2 = gzip.compress(b"BBBB")
    member3 = gzip.compress(b"CCCC")
    result1 = d.decompress_sync(member1 + member2, max_length=4)
    assert result1 == b"AAAA"
    result2 = d.decompress_sync(member3)
    assert result2 == b"BBBBCCCC"


def test_zlib_gzip_multi_member_walks_input_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every member is decoded from a bounded window, not from the whole tail.

    A fresh decompressor copies everything past the member it decodes into
    unused_data, so handing it the rest of the buffer at each boundary is
    quadratic: this blob would push ~6GiB through unused_data.
    """
    blob = gzip.compress(b"") * (MAX_DECOMPRESS_MEMBERS - 1)
    d = ZLibDecompressor(encoding="gzip")
    feeds: list[int] = []
    decompressobj = d._zlib_backend.decompressobj

    def recording(*, wbits: int) -> _RecordingDecompressObj:
        return _RecordingDecompressObj(decompressobj(wbits=wbits), feeds)

    monkeypatch.setattr(d._zlib_backend, "decompressobj", recording)
    assert d.decompress_sync(blob) == b""
    assert max(feeds) <= MEMBER_WINDOW_MAX
    assert sum(feeds) < 8 * len(blob)


def test_zlib_deflate_multi_member_window_doubles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A member outgrowing the window is fed in doubling slices, then capped.

    The schedule has to adapt to member size, because the peer chooses it: a
    fixed large window copies everything past a small member's end into
    unused_data (a member of window+1 bytes costs a whole window per byte of
    progress), while a fixed small one needs a call per 64 bytes of a large
    member.
    """
    co = zlib.compressobj(wbits=-15)
    small = co.compress(b"x") + co.flush()
    co = zlib.compressobj(wbits=-15)
    # Incompressible, so the member's wire size exceeds the whole ramp below.
    large = co.compress(os.urandom(200 * 1024)) + co.flush()

    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    feeds: list[int] = []
    decompressobj = d._zlib_backend.decompressobj

    def recording(*, wbits: int) -> _RecordingDecompressObj:
        return _RecordingDecompressObj(decompressobj(wbits=wbits), feeds)

    monkeypatch.setattr(d._zlib_backend, "decompressobj", recording)
    out = d.decompress_sync(small + large)

    assert len(out) == 1 + 200 * 1024
    ramp = [MEMBER_WINDOW_MIN << i for i in range(11)]  # 64 .. 65536
    assert ramp[-1] == MEMBER_WINDOW_MAX
    assert feeds[: len(ramp)] == ramp
    assert max(feeds) == MEMBER_WINDOW_MAX


def test_zlib_deflate_max_length_exhausted_mid_member() -> None:
    """Output can run out partway through a member, splitting the input in two.

    The bytes the cap left unconsumed stay on the decompressor as
    unconsumed_tail while the windows not yet fed become pending, so resuming
    has to feed unconsumed_tail first or the member decodes as garbage.
    """
    co = zlib.compressobj(wbits=-15)
    first_member = co.compress(b"x") + co.flush()
    body = b"A" * 100_000
    co = zlib.compressobj(wbits=-15)
    # Compresses small enough to span several windows, expands far past the cap.
    second_member = co.compress(body) + co.flush()
    assert len(second_member) > MEMBER_WINDOW_MIN

    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    out = d.decompress_sync(first_member + second_member, max_length=1000)
    split_seen = bool(d._decompressor.unconsumed_tail) and (
        d._pending_unused_data is not None
    )
    while d.data_available:
        out += d.decompress_sync(b"", max_length=1000)

    assert split_seen, "walk never suspended mid-member"
    assert out == b"x" + body


def test_zlib_deflate_member_flood_rejected() -> None:
    """Zero-output members never decrement max_length, cap must stop them."""
    co = zlib.compressobj(wbits=-15)
    empty_member = co.compress(b"") + co.flush()  # 2-byte empty raw-deflate member
    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(empty_member * 5000, max_length=262144)


def test_zlib_deflate_members_at_limit() -> None:
    """The allowance covers this many members, however little they hold."""
    co = zlib.compressobj(wbits=-15)
    empty_member = co.compress(b"") + co.flush()
    d = ZLibDecompressor(encoding="deflate", suppress_deflate_header=True)
    assert d.decompress_sync(empty_member * MAX_DECOMPRESS_MEMBERS) == b""


@pytest.mark.parametrize(
    "per_call",
    (2, 1000, 10 * MAX_DECOMPRESS_MEMBERS),
    ids=("pairs", "thousands", "joined"),
)
@pytest.mark.parametrize(
    ("make", "make_member"),
    (
        pytest.param(
            lambda: ZLibDecompressor(encoding="gzip"),
            lambda: gzip.compress(b""),
            id="gzip",
        ),
        pytest.param(
            lambda: ZLibDecompressor(encoding="deflate"),
            lambda: zlib.compress(b""),
            id="deflate",
        ),
        pytest.param(
            lambda: ZLibDecompressor(encoding="deflate", suppress_deflate_header=True),
            lambda: b"\x03\x00",
            id="raw-deflate",
        ),
        pytest.param(
            ZSTDDecompressor,
            lambda: zstandard.compress(b""),
            marks=pytest.mark.skipif(
                zstandard is None, reason="zstandard is not installed"
            ),
            id="zstd",
        ),
    ),
)
def test_member_limit_ignores_call_boundaries(
    make: Callable[[], ZLibDecompressor | ZSTDDecompressor],
    make_member: Callable[[], bytes],
    per_call: int,
) -> None:
    """A stream is cut off at the same member however it is split across calls.

    A member per call starts each one at a call boundary and a joined stream
    starts them all within a call, which each coding handles separately.
    """
    member = make_member()
    limit = _members_accepted(make(), member)
    assert MAX_DECOMPRESS_MEMBERS <= limit <= 3 * MAX_DECOMPRESS_MEMBERS

    d = make()
    for fed in range(0, limit, per_call):
        assert d.decompress_sync(member * min(per_call, limit - fed)) == b""
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(member)


@pytest.mark.parametrize(
    "per_call", (1, 4 * MAX_DECOMPRESS_MEMBERS), ids=("split", "joined")
)
@pytest.mark.parametrize(
    ("make", "make_member"),
    (
        pytest.param(
            lambda: ZLibDecompressor(encoding="gzip"),
            lambda: _gzip_member(MEMBER_COST),
            id="gzip",
        ),
        pytest.param(
            ZSTDDecompressor,
            lambda: zstandard.compress(os.urandom(MEMBER_COST)),
            marks=pytest.mark.skipif(
                zstandard is None, reason="zstandard is not installed"
            ),
            id="zstd",
        ),
    ),
)
def test_members_paying_their_way_never_run_out(
    make: Callable[[], ZLibDecompressor | ZSTDDecompressor],
    make_member: Callable[[], bytes],
    per_call: int,
) -> None:
    """A member at least as large as MEMBER_COST pays for the one after it."""
    member = make_member()
    count = 4 * MAX_DECOMPRESS_MEMBERS
    d = make()
    out = b"".join(
        d.decompress_sync(member * per_call) for _ in range(count // per_call)
    )
    assert out == make().decompress_sync(member) * count


# Members holding data, yet too small to pay for the one after them.
_SMALL_MEMBERS = (
    pytest.param(
        lambda: ZLibDecompressor(encoding="gzip"),
        lambda: gzip.compress(b"A" * 64),
        id="gzip",
    ),
    pytest.param(
        ZSTDDecompressor,
        lambda: zstandard.compress(b"A" * 64),
        marks=pytest.mark.skipif(
            zstandard is None, reason="zstandard is not installed"
        ),
        id="zstd",
    ),
)


@pytest.mark.parametrize(("make", "make_member"), _SMALL_MEMBERS)
def test_member_limit_ignores_max_length(
    make: Callable[[], ZLibDecompressor | ZSTDDecompressor],
    make_member: Callable[[], bytes],
) -> None:
    """A stream decoded a little at a time is cut off at the same member.

    The input a capped call leaves undecoded is handed back on later calls,
    where it must neither lose the credit it brought nor be credited again.
    """
    member = make_member()
    limit = _members_accepted(make(), member)

    d = make()
    out = d.decompress_sync(member * limit, max_length=1024)
    while d.data_available:
        out += d.decompress_sync(b"", max_length=1024)
    assert out == b"A" * 64 * limit
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(member)


@pytest.mark.parametrize(("make", "make_member"), _SMALL_MEMBERS)
def test_member_limit_measures_buffers_in_bytes(
    make: Callable[[], ZLibDecompressor | ZSTDDecompressor],
    make_member: Callable[[], bytes],
) -> None:
    """A buffer of wider items is cut off at the same member as its bytes.

    Its len() is a number of items, and input counted that way would earn a
    fraction of the credit it should.
    """
    # Four members a call, for a length that divides into four-byte items.
    group = make_member() * 4
    limit = _members_accepted(make(), group)
    # Annotated as bytes for zstd, though it takes whatever its backend does.
    view = cast(bytes, memoryview(group).cast("I"))

    d = make()
    for _ in range(limit):
        d.decompress_sync(view)
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(view)


def test_zlib_gzip_member_credit_restored_up_to_allowance() -> None:
    """Input earns spent credit back, but never beyond the initial allowance."""
    empty = gzip.compress(b"")
    d = ZLibDecompressor(encoding="gzip")
    d.decompress_sync(empty)
    allowance = _members_accepted(d, empty)

    d = ZLibDecompressor(encoding="gzip")
    d.decompress_sync(empty * (allowance // 2))
    # Worth several allowances, were the credit it earns not capped.
    d.decompress_sync(
        gzip.compress(os.urandom(4 * MAX_DECOMPRESS_MEMBERS * MEMBER_COST))
    )
    assert _members_accepted(d, empty) == allowance


@pytest.mark.parametrize("max_length", (0, 4096), ids=("unlimited", "capped"))
def test_zlib_gzip_many_members(max_length: int) -> None:
    """The allowance's worth of members decodes, resuming across calls."""
    member = gzip.compress(b"A" * 64)
    count = MAX_DECOMPRESS_MEMBERS
    d = ZLibDecompressor(encoding="gzip")
    out = d.decompress_sync(member * count, max_length=max_length)
    # The capped walk stops on budget with input still pending, so the
    # stream must not report complete until that input is drained.
    assert d.stream_complete == (max_length == 0)
    while d.data_available:
        out += d.decompress_sync(b"", max_length=max_length)
    assert d.stream_complete
    assert out == b"A" * 64 * count


def test_zlib_gzip_empty_members_interleaved_with_output() -> None:
    blob = (gzip.compress(b"") + gzip.compress(b"DATA")) * 20
    d = ZLibDecompressor(encoding="gzip")
    assert d.decompress_sync(blob) == b"DATA" * 20


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_frame_flood_rejected() -> None:
    """Multi-frame zstd shares the walk, so it shares the limit."""
    d = ZSTDDecompressor()
    with pytest.raises(TooManyMembersError):
        d.decompress_sync(zstandard.compress(b"") * 5000)


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_many_frames() -> None:
    frame = zstandard.compress(b"B" * 64)
    count = MAX_DECOMPRESS_MEMBERS
    d = ZSTDDecompressor()
    assert d.decompress_sync(frame * count) == b"B" * 64 * count


@pytest.mark.skipif(zstandard is None, reason="zstandard is not installed")
def test_zstd_empty_input_after_completed_frame() -> None:
    """An empty pump after a cleanly-ended frame is a no-op, not an EOFError."""
    d = ZSTDDecompressor()
    assert d.decompress_sync(zstandard.compress(b"payload")) == b"payload"
    assert d.stream_complete
    assert d.decompress_sync(b"") == b""
    assert d.stream_complete
