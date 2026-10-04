"""
Internal cookie handling helpers.

This module contains internal utilities for cookie parsing and manipulation.
These are not part of the public API and may change without notice.
"""

import re
from collections.abc import Sequence
from http.cookies import CookieError, Morsel

from .log import internal_logger

__all__ = (
    "parse_set_cookie_headers",
    "parse_cookie_header",
    "preserve_morsel_with_coded_value",
)

# Cookie parsing constants
# Allow more characters in cookie names to handle real-world cookies
# that don't strictly follow RFC standards (fixes #2683)
# RFC 6265 defines cookie-name token as per RFC 2616 Section 2.2,
# but many servers send cookies with characters like {} [] () etc.
# This makes the cookie parser more tolerant of real-world cookies
# while still providing some validation to catch obviously malformed names.
_COOKIE_NAME_RE = re.compile(r"^[!#$%&\'()*+\-./0-9:<=>?@A-Z\[\]^_`a-z{|}~]+$")
_COOKIE_KNOWN_ATTRS = frozenset(  # AKA Morsel._reserved
    (
        "path",
        "domain",
        "max-age",
        "expires",
        "secure",
        "httponly",
        "samesite",
        "partitioned",
        "version",
        "comment",
    )
)
_COOKIE_BOOL_ATTRS = frozenset(  # AKA Morsel._flags
    ("secure", "httponly", "partitioned")
)

# Implementation limits as permitted by RFC 6265 Section 6.1.
_MAX_COOKIES_PER_RESPONSE = 50
_MAX_COOKIE_PAIR_LENGTH = 4096
_MAX_COOKIE_ATTRIBUTE_VALUE_LENGTH = 1024
# Like Chromium's ParsedCookie::kMaxPairs, but more lenient.
_MAX_COOKIE_ATTRIBUTES = 32

# Where the next attribute can start: skips runs of ";" and whitespace.
_ATTRIBUTE_START_RE = re.compile(r"[^;\s]", re.ASCII)
_COOKIE_FORBIDDEN_CTL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_COOKIE_CTL_RE = re.compile(r"[\x00-\x1f\x7f]")

# SimpleCookie's pattern for parsing cookies with relaxed validation
# Based on http.cookies pattern but extended to allow more characters in cookie names
# to handle real-world cookies (fixes #2683)
_COOKIE_PATTERN = re.compile(
    r"""
    \s*                            # Optional whitespace at start of cookie
    (?P<key>                       # Start of group 'key'
    # aiohttp has extended to include [] for compatibility with real-world cookies
    [\w\d!#%&'~_`><@,:/\$\*\+\-\.\^\|\)\(\?\}\{\[\]]+   # Any word of at least one letter
    )                              # End of group 'key'
    (                              # Optional group: there may not be a value.
    \s*=\s*                          # Equal Sign
    (?P<val>                         # Start of group 'val'
    "(?:[^\\"]|\\.)*"                  # Any double-quoted string (properly closed)
    |                                  # or
    "[^";]*                            # Unmatched opening quote (differs from SimpleCookie - issue #7993)
    |                                  # or
    # Special case for "expires" attr - RFC 822, RFC 850, RFC 1036, RFC 1123
    (\w{3,6}day|\w{3}),\s              # Day of the week or abbreviated day (with comma)
    [\w\d\s-]{9,11}\s[\d:]{8}\s        # Date and time in specific format
    (GMT|[+-]\d{4})                     # Timezone: GMT or RFC 2822 offset like -0000, +0100
                                        # NOTE: RFC 2822 timezone support is an aiohttp extension
                                        # for issue #4493 - SimpleCookie does NOT support this
    |                                  # or
    # ANSI C asctime() format: "Wed Jun  9 10:18:14 2021"
    # NOTE: This is an aiohttp extension for issue #4327 - SimpleCookie does NOT support this format
    \w{3}\s+\w{3}\s+[\s\d]\d\s+\d{2}:\d{2}:\d{2}\s+\d{4}
    |                                  # or
    [\w\d!#%&'~_`><@,:/\$\*\+\-\.\^\|\)\(\?\}\{\=\[\]]*      # Any word or empty string
    )                                # End of group 'val'
    )?                             # End of optional value group
    \s*                            # Any number of spaces.
    (\s+|;|$)                      # Ending either at space, semicolon, or EOS.
    """,
    re.VERBOSE | re.ASCII,
)


def preserve_morsel_with_coded_value(cookie: Morsel[str]) -> Morsel[str]:
    """
    Preserve a Morsel's coded_value exactly as received from the server.

    This function ensures that cookie encoding is preserved exactly as sent by
    the server, which is critical for compatibility with old servers that have
    strict requirements about cookie formats.

    This addresses the issue described in https://github.com/aio-libs/aiohttp/pull/1453
    where Python's SimpleCookie would re-encode cookies, breaking authentication
    with certain servers.

    Args:
        cookie: A Morsel object from SimpleCookie

    Returns:
        A Morsel object with preserved coded_value

    """
    # Don't look up cookie.key in the Morsel: it maps attribute names, so a
    # cookie named ``path`` would return the Path attribute.
    mrsl_val: Morsel[str] = Morsel()
    # We use __setstate__ instead of the public set() API because it allows us to
    # bypass validation and set already validated state. This is more stable than
    # setting protected attributes directly and unlikely to change since it would
    # break pickling.
    try:
        mrsl_val.__setstate__(  # type: ignore[attr-defined]
            {
                "key": cookie.key,
                "value": cookie.value,
                "coded_value": cookie.coded_value,
            }
        )
    except CookieError:
        return cookie
    return mrsl_val


_unquote_sub = re.compile(r"\\(?:([0-3][0-7][0-7])|(.))").sub


def _unquote_replace(m: re.Match[str]) -> str:
    """
    Replace function for _unquote_sub regex substitution.

    Handles escaped characters in cookie values:
    - Octal sequences are converted to their character representation
    - Other escaped characters are unescaped by removing the backslash
    """
    if m[1]:
        return chr(int(m[1], 8))
    return m[2]


def _unquote(value: str) -> str:
    """
    Unquote a cookie value.

    Vendored from http.cookies._unquote to ensure compatibility.

    Note: The original implementation checked for None, but we've removed
    that check since all callers already ensure the value is not None.
    """
    # If there aren't any doublequotes,
    # then there can't be any special characters.  See RFC 2109.
    if len(value) < 2:
        return value
    if value[0] != '"' or value[-1] != '"':
        return value

    # We have to assume that we must decode this string.
    # Down to work.

    # Remove the "s
    value = value[1:-1]

    # Check for special sequences.  Examples:
    #    \012 --> \n
    #    \"   --> "
    #
    return _unquote_sub(_unquote_replace, value)


def parse_cookie_header(header: str) -> list[tuple[str, Morsel[str]]]:
    """
    Parse a Cookie header according to RFC 6265 Section 5.4.

    Cookie headers contain only name-value pairs separated by semicolons.
    There are no attributes in Cookie headers - even names that match
    attribute names (like 'path' or 'secure') should be treated as cookies.

    This parser uses _COOKIE_PATTERN to properly handle quoted values that may
    contain semicolons. When the regex fails to match a malformed cookie, it
    falls back to simple parsing to ensure subsequent cookies are not lost
    https://github.com/aio-libs/aiohttp/issues/11632

    Args:
        header: The Cookie header value to parse

    Returns:
        List of (name, Morsel) tuples for compatibility with SimpleCookie.update()
    """
    if not header:
        return []

    cookies: list[tuple[str, Morsel[str]]] = []
    morsel: Morsel[str]
    i = 0
    n = len(header)

    invalid_names = []
    while i < n:
        # Find the next cookie-pair
        match = _COOKIE_PATTERN.match(header, i)
        if not match:
            # Fallback for malformed cookies https://github.com/aio-libs/aiohttp/issues/11632
            # Find next semicolon to skip or attempt simple key=value parsing
            next_semi = header.find(";", i)
            eq_pos = header.find("=", i)

            # Try to extract key=value if '=' comes before ';'
            if eq_pos != -1 and (next_semi == -1 or eq_pos < next_semi):
                end_pos = next_semi if next_semi != -1 else n
                key = header[i:eq_pos].strip()
                value = header[eq_pos + 1 : end_pos].strip()

                # Validate the name (same as regex path)
                if not _COOKIE_NAME_RE.match(key):
                    invalid_names.append(key)
                else:
                    morsel = Morsel()
                    try:
                        morsel.__setstate__(  # type: ignore[attr-defined]
                            {
                                "key": key,
                                "value": _unquote(value),
                                "coded_value": value,
                            }
                        )
                    except CookieError:
                        pass
                    else:
                        cookies.append((key, morsel))

            # Move to next cookie or end
            i = next_semi + 1 if next_semi != -1 else n
            continue

        key = match.group("key")
        value = match.group("val") or ""
        i = match.end(0)

        # Validate the name
        if not key or not _COOKIE_NAME_RE.match(key):
            invalid_names.append(key)
            continue

        # Create new morsel
        morsel = Morsel()
        # Preserve the original value as coded_value (with quotes if present)
        # We use __setstate__ instead of the public set() API because it allows us to
        # bypass validation and set already validated state. This is more stable than
        # setting protected attributes directly and unlikely to change since it would
        # break pickling.
        try:
            morsel.__setstate__(  # type: ignore[attr-defined]
                {"key": key, "value": _unquote(value), "coded_value": value}
            )
        except CookieError:
            continue

        cookies.append((key, morsel))

    if invalid_names:
        internal_logger.debug(
            "Cannot load cookie. Illegal cookie names: %r", invalid_names
        )

    return cookies


def _encoded_length(text: str) -> int | None:
    """Return the UTF-8 length of text, or None if it can't be encoded."""
    if text.isascii():
        return len(text)
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _apply_cookie_attributes(morsel: Morsel[str], attributes: str) -> None:
    """Set the recognized attributes from the text after the cookie-pair.

    The field must already be free of control characters other than tab.
    """
    # Walk with the cookie pattern so a quoted value keeps its ";". Missing
    # semicolons between attributes are tolerated; every match is an attribute
    # of this cookie, never a new cookie.
    index = 0
    end = len(attributes)
    for _ in range(_MAX_COOKIE_ATTRIBUTES):
        if index >= end:
            break
        if (attribute_match := _COOKIE_PATTERN.match(attributes, index)) is None:
            # Skip a malformed segment and any run of ";" or whitespace after it.
            if (
                not (next_index := attributes.find(";", index) + 1)
                or (start := _ATTRIBUTE_START_RE.search(attributes, next_index)) is None
            ):
                break
            index = start.start()
            continue
        index = attribute_match.end()
        lower_key = attribute_match.group("key").lower()
        if lower_key not in _COOKIE_KNOWN_ATTRS:
            # RFC 6265 Section 5.2: ignore unknown attributes.
            continue
        if lower_key not in morsel._reserved:  # type: ignore[attr-defined]
            # Python versions before 3.14 do not expose Partitioned.
            continue

        # The key and value are checked here, so skip Morsel.__setitem__'s checks.
        if lower_key in _COOKIE_BOOL_ATTRS:
            # Like Firefox, a flag's value is ignored.
            dict.__setitem__(morsel, lower_key, True)
            continue
        attr_value = attribute_match.group("val") or ""
        if (
            len(attr_value) <= _MAX_COOKIE_ATTRIBUTE_VALUE_LENGTH
            and attr_value.isascii()
            and attr_value[:1] != '"'
            and "\t" not in attr_value
        ):
            # The field has no other control characters and nothing to unquote.
            dict.__setitem__(morsel, lower_key, attr_value)
            continue
        attr_value_length = _encoded_length(attr_value)
        if (
            attr_value_length is None
            or attr_value_length > _MAX_COOKIE_ATTRIBUTE_VALUE_LENGTH
        ):
            continue
        # Patched CPython rejects control characters, even ones produced by
        # unquoting, so ignore such an attribute rather than raise.
        if _COOKIE_CTL_RE.search(value := _unquote(attr_value)) is None:
            dict.__setitem__(morsel, lower_key, value)


def _parse_quoted_pair(header: str) -> tuple[str, str, int] | None:
    """Parse a first pair whose quoted value contains ";".

    aiohttp has always accepted these. Returns the name, the quoted value and
    where the attributes start, or None to split at the first ";" instead.
    """
    match = _COOKIE_PATTERN.match(header)
    if match is None or not (value := match.group("val")):
        return None
    if not (value.startswith('"') and value.endswith('"') and ";" in value):
        return None
    tail = header[match.end("val") :].lstrip(" \t")
    if tail and not tail.startswith(";"):
        return None
    return match.group("key"), value, len(header) - len(tail) + bool(tail)


def parse_set_cookie_headers(headers: Sequence[str]) -> list[tuple[str, Morsel[str]]]:
    """Parse Set-Cookie fields into at most one cookie per field.

    Fields with control characters, oversized or nameless pairs, names outside
    the allowlist, or tabs in the pair are skipped.
    """
    parsed_cookies: list[tuple[str, Morsel[str]]] = []
    over_limit = 0

    for position, header in enumerate(headers):
        if len(parsed_cookies) >= _MAX_COOKIES_PER_RESPONSE:
            over_limit = len(headers) - position
            break
        if not header or _COOKIE_FORBIDDEN_CTL_RE.search(header) is not None:
            continue

        if (pair_end := header.find(";")) == -1:
            pair_end = attributes_start = len(header)
        else:
            attributes_start = pair_end + 1
        # A quote before the first ";" may start a quoted value containing ";".
        if header.find('"', 0, pair_end) != -1 and (
            quoted := _parse_quoted_pair(header)
        ):
            key, coded_value, attributes_start = quoted
        else:
            key, sep, coded_value = header[:pair_end].partition("=")
            if not sep:
                continue

        key = key.strip(" \t")
        coded_value = coded_value.strip(" \t")

        if not key:
            continue
        if not _COOKIE_NAME_RE.match(key):
            internal_logger.warning("Can not load cookies: Illegal cookie name %r", key)
            continue
        pair_length = _encoded_length(key + coded_value)
        if pair_length is None or pair_length > _MAX_COOKIE_PAIR_LENGTH:
            continue

        value = _unquote(coded_value)
        if _COOKIE_CTL_RE.search(value) is not None:
            continue
        morsel: Morsel[str] = Morsel()
        try:
            morsel.__setstate__(  # type: ignore[attr-defined]
                {"key": key, "value": value, "coded_value": coded_value}
            )
        except CookieError:
            continue

        _apply_cookie_attributes(morsel, header[attributes_start:])
        parsed_cookies.append((key, morsel))

    if (invalid := len(headers) - over_limit - len(parsed_cookies)) or over_limit:
        internal_logger.debug(
            "Ignored %d invalid Set-Cookie field(s) and %d over the %d-cookie limit",
            invalid,
            over_limit,
            _MAX_COOKIES_PER_RESPONSE,
        )
    return parsed_cookies
