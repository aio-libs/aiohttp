import pytest

from aiohttp import streams


DATA = b'line1\nline2\nline3\n'


def chunkify(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i+n]


def create_stream(loop):
    stream = streams.StreamReader(loop=loop)
    stream.feed_data(DATA)
    stream.feed_eof()
    return stream


@pytest.mark.run_loop
async def test_stream_reader_lines(loop):
    line_iter = iter(DATA.splitlines(keepends=True))
    async for line in create_stream(loop):
        assert line == next(line_iter, None)
    pytest.raises(StopIteration, next, line_iter)


@pytest.mark.run_loop
async def test_stream_reader_chunks_complete(loop):
    """Tests if chunked iteration works if the chunking works out
    (i.e. the data is divisible by the chunk size)
    """
    chunk_iter = chunkify(DATA, 9)
    async for line in create_stream(loop).iter_chunked(9):
        assert line == next(chunk_iter, None)
    pytest.raises(StopIteration, next, chunk_iter)


@pytest.mark.run_loop
async def test_stream_reader_chunks_incomplete(loop):
    """Tests if chunked iteration works if the last chunk is incomplete"""
    chunk_iter = chunkify(DATA, 8)
    async for line in create_stream(loop).iter_chunked(8):
        assert line == next(chunk_iter, None)
    pytest.raises(StopIteration, next, chunk_iter)


@pytest.mark.run_loop
async def test_data_queue_empty(loop):
    """Tests that async looping yields nothing if nothing is there"""
    buffer = streams.DataQueue(loop=loop)
    buffer.feed_eof()

    async for _ in buffer:  # NOQA
        assert False


@pytest.mark.run_loop
async def test_data_queue_items(loop):
    """Tests that async looping yields objects identically"""
    buffer = streams.DataQueue(loop=loop)

    items = [object(), object()]
    buffer.feed_data(items[0], 1)
    buffer.feed_data(items[1], 1)
    buffer.feed_eof()

    item_iter = iter(items)
    async for item in buffer:
        assert item is next(item_iter, None)
    pytest.raises(StopIteration, next, item_iter)


@pytest.mark.run_loop
async def test_stream_reader_iter_any(loop):
    it = iter([b'line1\nline2\nline3\n'])
    async for raw in create_stream(loop).iter_any():
        assert raw == next(it)
