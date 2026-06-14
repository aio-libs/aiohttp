# Vulnerability reporting guidelines for aiohttp

- Most reports need a reproducer that makes an HTTP request. Attackers do not
  have direct access to aiohttp internals; a report must demonstrate how an
  attacker can actually exploit it.
- Any report about excessive memory use must generally use a payload of
  atlest 1 MiB and show that it completely bypasses any size restrictions.
  asyncio reads upto 256 KiB from the socket at a time, so many parts of
  aiohttp assume that 256 KiB are being loaded into memory all the time for
  every request.
