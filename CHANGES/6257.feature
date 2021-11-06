This feature adds strategy argument to StreamResponse.enable_compression() method.
For example, tests show that download speed becomes 2x faster for .png images when using
`zlib.Z_RLE` compression srategy
