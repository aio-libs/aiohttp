Don't require ssl module to run.

aiohttp does not require SSL to function. The codepaths involved with
SSL will only be hit upon SSL usage. Raise `RuntimeError` if https
protocol is required but ssl module is not present.
