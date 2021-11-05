Added `strategy` argument to `StreamResponse.enable_compression()` method
The end users can significantly speed up compression using this parameter.
Example of usage:
```
async def get_png(request):
    response = web.FileResponse("./content.png")
    response.enable_compression(strategy=zlib.Z_RLE)
    return response
```
