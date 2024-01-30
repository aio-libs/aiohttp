Added an :py:exc:`~aiohttp.InvalidRedirectURL` exception which is now raised instead of
:py:exc:`ValueError` or :py:exc:`~aiohttp.InvalidURL` when the redirect URL
is invalid -- by :user:`setla`.

The :py:exc:`~aiohttp.InvalidURL` exception (and
:py:exc:`~aiohttp.InvalidRedirectURL`, that inherits it), now exposes
a ``description`` property with the text explanation of
the error details.
