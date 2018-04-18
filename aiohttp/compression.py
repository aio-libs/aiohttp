import enum
import zlib

from .http_exceptions import ContentEncodingError


try:
    import brotli
except ImportError:  # pragma: nocover
    brotli = None


if brotli is None:
    DEFAULT_ACCEPT_ENCODING = 'gzip, deflate'
else:
    DEFAULT_ACCEPT_ENCODING = 'gzip, deflate, br'


class ContentCoding(enum.Enum):
    # The content codings that we have support for.
    #
    # Additional registered codings are listed at:
    # https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding
    deflate = 'deflate'
    gzip = 'gzip'
    identity = 'identity'
    br = 'br'

    @classmethod
    def get_from_accept_encoding(cls, accept_encoding):
        accept_encoding = accept_encoding.lower()
        for coding in cls:
            if coding.value in accept_encoding:
                if coding == cls.br and brotli is None:
                    continue
                return coding

    @classmethod
    def values(cls):
        _values = getattr(cls, '_values', None)
        if _values is None:
            cls._values = _values = frozenset({c.value for c in cls})
        return _values


def get_compressor(encoding):
    if encoding == 'gzip':
        return ZlibCompressor.gzip()
    elif encoding == 'deflate':
        return ZlibCompressor.deflate()
    elif encoding == 'br':
        return BrotliCompressor()
    elif encoding == 'identity':
        return None
    else:
        raise RuntimeError('Encoding is %s not supported' % encoding)


class ZlibCompressor:

    def __init__(self, wbits):
        self._compress = zlib.compressobj(wbits=wbits)
        self._finished = False

    @classmethod
    def gzip(cls):
        return cls(wbits=16 + zlib.MAX_WBITS)

    @classmethod
    def deflate(cls):
        return cls(wbits=-zlib.MAX_WBITS)

    def compress(self, data):
        return self._compress.compress(data)

    def finish(self):
        if self._finished:
            raise RuntimeError('Compressor is finished!')
        self._finished = True
        return self._compress.flush()


class BrotliCompressor:

    def __init__(self):
        if brotli is None:  # pragma: no cover
            raise ContentEncodingError(
                'Can not decode content-encoding: brotli (br). '
                'Please install `brotlipy`')
        self._compress = brotli.Compressor()

    def compress(self, data):
        return self._compress.compress(data)

    def finish(self):
        return self._compress.finish()


def decompress(encoding, data):
    if encoding == 'identity':
        return data
    decompressor = get_decompressor(encoding)
    decompressed = decompressor.decompress(data) + decompressor.flush()
    if not decompressor.eof:
        raise ContentEncodingError(
            'Can not decode content-encoding: %s' % encoding)
    return decompressed


def get_decompressor(encoding):
    if encoding == 'gzip':
        return GzipDecompressor()
    elif encoding == 'deflate':
        return DeflateDecompressor()
    elif encoding == 'br':
        return BrotliDecompressor()
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
        if isinstance(chunk, bytearray):
            chunk = bytes(chunk)
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
