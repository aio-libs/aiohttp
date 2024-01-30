Added an ``InvalidRedirectURL`` exception which is now raised instead of
:py:exc:`ValueError` or ``InvalidURL`` when the redirect URL
is invalid -- by :user:`setla`.

The ``InvalidURL`` exception (and
``InvalidRedirectURL``, that inherits it), now exposes
a ``description`` property with the text explanation of
the error details.
