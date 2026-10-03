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
# RFC 10025 defines cookie-name as a token,
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

# RFC 10025 section 5.3 allows user agents to impose implementation limits.
# These limits bound work performed per Set-Cookie field.
_MAX_COOKIES_PER_RESPONSE = 50
_MAX_COOKIE_PAIR_LENGTH = 4096
_MAX_COOKIE_ATTRIBUTE_VALUE_LENGTH = 1024

_COOKIE_FORBIDDEN_CTL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_COOKIE_DECODED_CTL_RE = re.compile(r"[\x00-\x1f\x7f]")

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
    # Morsel is also a mapping of reserved attribute names to strings. Looking
    # up the cookie name in it would return an attribute string for valid
    # cookie-pair names such as ``path`` or ``secure``.
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
    Parse a Cookie header according to RFC 10025.

    Cookie headers contain only name-value pairs separated by semicolons.
    There are no attributes in Cookie headers - even names that match
    attribute names (like 'path' or 'secure') should be treated as cookies.

    This parser uses the same regex-based approach as parse_set_cookie_headers
    to properly handle quoted values that may contain semicolons. When the
    regex fails to match a malformed cookie, it falls back to simple parsing
    to ensure subsequent cookies are not lost
    https://github.com/aio-libs/aiohttp/issues/11632

    Args:
        header: The Cookie header value to parse

    Returns:
        List of (name, Morsel) tuples for compatibility with SimpleCookie.update()
    """
    if not header:
        return []

    morsel: Morsel[str]
    cookies: list[tuple[str, Morsel[str]]] = []
    i = 0
    n = len(header)

    invalid_names = []
    while i < n:
        # Use the same pattern as parse_set_cookie_headers to find cookies
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


def parse_set_cookie_headers(headers: Sequence[str]) -> list[tuple[str, Morsel[str]]]:
    """
    Parse Set-Cookie fields into at most one cookie per field.

    RFC 10025 defines each Set-Cookie field as one name-value pair followed by
    attributes. Unknown attributes are ignored rather than interpreted as
    additional cookies. The parser applies finite user-agent limits before
    constructing a Morsel.

    Python's cookie types cannot safely or unambiguously serialize every name
    RFC 10025's parsing algorithm permits. Nameless cookies, names outside
    aiohttp's existing compatibility allowlist, and cookie pairs containing
    internal horizontal tabs are rejected as an explicit user-agent
    cookie-policy choice permitted by section 5.3. Quoted values retain
    aiohttp's historical decoded ``value`` and original ``coded_value``
    representations. Controls introduced by that compatibility decoding are
    rejected so application-visible cookie state remains free of controls.
    """
    parsed_cookies: list[tuple[str, Morsel[str]]] = []

    for header in headers:
        if len(parsed_cookies) >= _MAX_COOKIES_PER_RESPONSE:
            break
        if not header or _COOKIE_FORBIDDEN_CTL_RE.search(header) is not None:
            continue

        parsed_pair: tuple[str, str] | None = None
        attributes_start = len(header)

        # aiohttp has historically accepted semicolons inside a properly
        # quoted first value. Preserve that narrow compatibility extension,
        # while never interpreting its contents as additional cookies.
        compatibility_match = _COOKIE_PATTERN.match(header, 0)
        compatibility_value = (
            compatibility_match.group("val") if compatibility_match else None
        )
        if (
            compatibility_match is not None
            and compatibility_value is not None
            and compatibility_value.startswith('"')
            and compatibility_value.endswith('"')
            and ";" in compatibility_value
        ):
            tail = header[compatibility_match.end("val") :].lstrip(" \t")
            if not tail or tail.startswith(";"):
                parsed_pair = (
                    compatibility_match.group("key"),
                    compatibility_value,
                )
                attributes_start = compatibility_match.end("val")
                while (
                    attributes_start < len(header) and header[attributes_start] in " \t"
                ):
                    attributes_start += 1
                if attributes_start < len(header) and header[attributes_start] == ";":
                    attributes_start += 1

        if parsed_pair is None:
            pair_end = header.find(";")
            if pair_end == -1:
                pair_end = len(header)
            else:
                attributes_start = pair_end + 1
            name_value_pair = header[:pair_end]
            if "=" in name_value_pair:
                key, coded_value = name_value_pair.split("=", 1)
                parsed_pair = (key, coded_value)
            else:
                parsed_pair = ("", name_value_pair)

        key, coded_value = parsed_pair
        key = key.strip(" \t")
        coded_value = coded_value.strip(" \t")

        if (
            not key
            or not _COOKIE_NAME_RE.match(key)
            or "\t" in key
            or "\t" in coded_value
        ):
            continue
        try:
            pair_length = len(key.encode("utf-8")) + len(coded_value.encode("utf-8"))
        except UnicodeEncodeError:
            continue
        if pair_length > _MAX_COOKIE_PAIR_LENGTH:
            continue

        value = _unquote(coded_value)
        if _COOKIE_DECODED_CTL_RE.search(value) is not None:
            continue
        morsel: Morsel[str] = Morsel()
        try:
            morsel.__setstate__(  # type: ignore[attr-defined]
                {"key": key, "value": value, "coded_value": coded_value}
            )
        except CookieError:
            continue

        # Scan the original field by increasing offsets rather than repeatedly
        # partitioning a shrinking suffix.
        header_length = len(header)
        while attributes_start < header_length:
            attribute_end = header.find(";", attributes_start)
            if attribute_end == -1:
                attribute_end = header_length
            cookie_attribute = header[attributes_start:attribute_end]
            attributes_start = attribute_end + 1
            # Preserve aiohttp's established tolerance for omitted semicolons
            # between recognizable attributes. Every parsed pair remains an
            # attribute of the first cookie; it can never create another one.
            attribute_index = 0
            while attribute_index < len(cookie_attribute):
                attribute_match = _COOKIE_PATTERN.match(
                    cookie_attribute, attribute_index
                )
                if attribute_match is None:
                    break
                attribute_index = attribute_match.end()
                attr_key = attribute_match.group("key")
                attr_value = attribute_match.group("val") or ""

                try:
                    attr_value_length = len(
                        attr_value.encode("utf-8", "surrogateescape")
                    )
                except UnicodeEncodeError:
                    continue
                if attr_value_length > _MAX_COOKIE_ATTRIBUTE_VALUE_LENGTH:
                    continue

                lower_key = attr_key.lower()
                if lower_key not in _COOKIE_KNOWN_ATTRS:
                    # RFC 10025: ignore unrecognized cookie attributes.
                    continue
                if not morsel.isReservedKey(lower_key):
                    # Python versions before 3.14 do not expose Partitioned.
                    continue
                if lower_key in _COOKIE_BOOL_ATTRS:
                    morsel[lower_key] = True
                    continue

                # Retained attributes are included by Morsel.OutputString().
                # Ignore values Python's serializer cannot represent safely.
                if "\t" in attr_value:
                    continue
                try:
                    attr_value.encode("utf-8")
                except UnicodeEncodeError:
                    continue
                morsel[lower_key] = attr_value

        parsed_cookies.append((key, morsel))

    return parsed_cookies
