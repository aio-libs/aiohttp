import zlib

from .http_exceptions import ContentEncodingError


try:
    import brotli
except ImportError:  # pragma: nocover
    brotli = None


def get_compressor(encoding):
    if encoding == 'gzip':
        return zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    elif encoding == 'deflate':
        return zlib.compressobj(wbits=-zlib.MAX_WBITS)
    else:
        raise RuntimeError('Encoding is %s not supported' % encoding)


def decompress(encoding, data):
    decompressor = get_decompressor(encoding)
    decompressed = decompressor.decompress(data) + decompressor.flush()
    if not decompressor.eof:
        raise ContentEncodingError(
            'Can not decode content-encoding: %s' % encoding)
    return decompressed


def get_decompressor(encoding):
    if encoding == 'br':
        return BrotliDecompressor()
    elif encoding == 'gzip':
        return GzipDecompressor()
    elif encoding == 'deflate':
        return DeflateDecompressor()
    else:
        raise RuntimeError('Encoding %s is not supported' % encoding)


class DeflateDecompressor:

    __slots__ = ('_decompressor', '_started_decoding')

    def __init__(self):
        self._decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
        self._started_decoding = False

    def decompress(self, chunk):
        try:
            decompressed = self._decompressor.decompress(chunk)
            if decompressed:
                self._started_decoding = True
            return decompressed
        except Exception:
            # Try another wbits setting. See #1918 for details.
            if not self._started_decoding:
                self._decompressor = zlib.decompressobj()
                return self.decompress(chunk)
            raise

    def flush(self):
        return self._decompressor.flush()

    @property
    def eof(self):
        return self._decompressor.eof


class GzipDecompressor:

    __slots__ = ('_decompressor',)

    def __init__(self):
        self._decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)

    def decompress(self, chunk):
        return self._decompressor.decompress(chunk)

    def flush(self):
        return self._decompressor.flush()

    @property
    def eof(self):
        return self._decompressor.eof


class BrotliDecompressor:

    __slots__ = ('_decompressor', '_eof')

    def __init__(self):
        if brotli is None:  # pragma: no cover
            raise ContentEncodingError(
                'Can not decode content-encoding: brotli (br). '
                'Please install `brotlipy`')
        self._decompressor = brotli.Decompressor()
        self._eof = None

    def decompress(self, chunk):
        return self._decompressor.decompress(chunk)

    def flush(self):
        # Brotli decompression is eager.
        return b''

    @property
    def eof(self):
        if self._eof is not None:
            return self._eof
        try:
            self._decompressor.finish()
            self._eof = True
        except brotli.Error:
            self._eof = False
        return self._eof
