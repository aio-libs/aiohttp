Disabled implicit switch-back to pure python mode. The build fails loudly if aiohttp
cannot be compiled with C Accelerators.  Use `AIOHTTP_NO_EXTENSIONS=1` to explicitly
disable C Extensions complication and switch to Pure-Python mode.  Note that Pure-Python
mode is significantly slower than compiled one.
