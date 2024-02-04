Added 5 new exceptions: :py:exc:`~aiohttp.InvalidUrlClientError`, :py:exc:`~aiohttp.RedirectClientError`,
:py:exc:`~aiohttp.NonHttpUrlClientError`, :py:exc:`~aiohttp.InvalidUrlRedirectClientError`,
:py:exc:`~aiohttp.NonHttpUrlRedirectClientError`

:py:exc:`~aiohttp.InvalidUrlRedirectClientError`, :py:exc:`~aiohttp.NonHttpUrlRedirectClientError`
are raised instead of :py:exc:`ValueError` or :py:exc:`~aiohttp.InvalidURL` when the redirect URL is invalid. Classes
:py:exc:`~aiohttp.InvalidUrlClientError`, :py:exc:`~aiohttp.RedirectClientError`,
:py:exc:`~aiohttp.NonHttpUrlClientError` are base for them.

The :py:exc:`~aiohttp.InvalidURL` now exposes a ``description`` property with the text explanation of the error details.
by :user:`setla`.
