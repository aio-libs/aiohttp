"""Tests for internal cookie helper functions."""

from http.cookies import (
    CookieError,
    Morsel,
    SimpleCookie,
    _unquote as simplecookie_unquote,
)

import pytest

from aiohttp import _cookie_helpers as helpers
from aiohttp._cookie_helpers import (
    _unquote,
    parse_cookie_header,
    parse_set_cookie_headers,
    preserve_morsel_with_coded_value,
)


def test_known_attrs_is_superset_of_morsel_reserved() -> None:
    """Test that _COOKIE_KNOWN_ATTRS contains all Morsel._reserved attributes."""
    # Get Morsel._reserved attributes (lowercase)
    morsel_reserved = {attr.lower() for attr in Morsel._reserved}  # type: ignore[attr-defined]

    # _COOKIE_KNOWN_ATTRS should be a superset of morsel_reserved
    assert (
        helpers._COOKIE_KNOWN_ATTRS >= morsel_reserved
    ), f"_COOKIE_KNOWN_ATTRS is missing: {morsel_reserved - helpers._COOKIE_KNOWN_ATTRS}"


def test_bool_attrs_is_superset_of_morsel_flags() -> None:
    """Test that _COOKIE_BOOL_ATTRS contains all Morsel._flags attributes."""
    # Get Morsel._flags attributes (lowercase)
    morsel_flags = {attr.lower() for attr in Morsel._flags}  # type: ignore[attr-defined]

    # _COOKIE_BOOL_ATTRS should be a superset of morsel_flags
    assert (
        helpers._COOKIE_BOOL_ATTRS >= morsel_flags
    ), f"_COOKIE_BOOL_ATTRS is missing: {morsel_flags - helpers._COOKIE_BOOL_ATTRS}"


def test_preserve_morsel_with_coded_value() -> None:
    """Test preserve_morsel_with_coded_value preserves coded_value exactly."""
    # Create a cookie with a coded_value different from value
    cookie: Morsel[str] = Morsel()
    cookie.set("test_cookie", "decoded value", "encoded%20value")

    # Preserve the coded_value
    result = preserve_morsel_with_coded_value(cookie)

    # Check that all values are preserved
    assert result.key == "test_cookie"
    assert result.value == "decoded value"
    assert result.coded_value == "encoded%20value"

    # Should be a different Morsel instance
    assert result is not cookie


def test_preserve_morsel_with_coded_value_no_coded_value() -> None:
    """Test preserve_morsel_with_coded_value when coded_value is same as value."""
    cookie: Morsel[str] = Morsel()
    cookie.set("test_cookie", "simple_value", "simple_value")

    result = preserve_morsel_with_coded_value(cookie)

    assert result.key == "test_cookie"
    assert result.value == "simple_value"
    assert result.coded_value == "simple_value"


def test_parse_set_cookie_headers_simple() -> None:
    """Test parse_set_cookie_headers with simple cookies."""
    headers = ["name=value", "session=abc123"]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 2
    assert result[0][0] == "name"
    assert result[0][1].key == "name"
    assert result[0][1].value == "value"
    assert result[1][0] == "session"
    assert result[1][1].key == "session"
    assert result[1][1].value == "abc123"


def test_parse_set_cookie_headers_with_attributes() -> None:
    """Test parse_set_cookie_headers with cookie attributes."""
    headers = [
        "sessionid=value123; Path=/; HttpOnly; Secure",
        "user=john; Domain=.example.com; Max-Age=3600",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 2

    # First cookie
    name1, morsel1 = result[0]
    assert name1 == "sessionid"
    assert morsel1.value == "value123"
    assert morsel1["path"] == "/"
    assert morsel1["httponly"] is True
    assert morsel1["secure"] is True

    # Second cookie
    name2, morsel2 = result[1]
    assert name2 == "user"
    assert morsel2.value == "john"
    assert morsel2["domain"] == ".example.com"
    assert morsel2["max-age"] == "3600"


def test_parse_set_cookie_headers_special_chars_in_names() -> None:
    """Test parse_set_cookie_headers accepts special characters in names (#2683)."""
    # These should be accepted with relaxed validation
    headers = [
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}=value1",
        "cookie[index]=value2",
        "cookie(param)=value3",
        "cookie:name=value4",
        "cookie@domain=value5",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 5
    expected_names = [
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}",
        "cookie[index]",
        "cookie(param)",
        "cookie:name",
        "cookie@domain",
    ]

    for i, (name, morsel) in enumerate(result):
        assert name == expected_names[i]
        assert morsel.key == expected_names[i]
        assert morsel.value == f"value{i+1}"


def test_parse_set_cookie_headers_invalid_names() -> None:
    """Test parse_set_cookie_headers rejects truly invalid cookie names."""
    # These should be rejected even with relaxed validation
    headers = [
        "invalid\tcookie=value",  # Tab character
        "invalid\ncookie=value",  # Newline
        "invalid\rcookie=value",  # Carriage return
        "\x00badname=value",  # Null character
        "name with spaces=value",  # Spaces in name
    ]

    result = parse_set_cookie_headers(headers)

    # All should be skipped
    assert len(result) == 0


def test_parse_set_cookie_headers_empty_and_invalid() -> None:
    """Test parse_set_cookie_headers handles empty and invalid formats."""
    headers = [
        "",  # Empty header
        "   ",  # Whitespace only
        "=value",  # No name
        "name=",  # Empty value (should be accepted)
        "justname",  # No value (should be skipped)
        "path=/",  # Reserved attribute as name (should be skipped)
        "Domain=.com",  # Reserved attribute as name (should be skipped)
    ]

    result = parse_set_cookie_headers(headers)

    # Only "name=" should be accepted
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1].value == ""


def test_parse_set_cookie_headers_quoted_values() -> None:
    """Test parse_set_cookie_headers handles quoted values correctly."""
    headers = [
        'name="quoted value"',
        'session="with;semicolon"',
        'data="with\\"escaped\\""',
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 3
    assert result[0][1].value == "quoted value"
    assert result[1][1].value == "with;semicolon"
    assert result[2][1].value == 'with"escaped"'


@pytest.mark.parametrize(
    "header",
    [
        'session="abc;xyz"; token=123',
        'data="value;with;multiple;semicolons"; next=cookie',
        'complex="a=b;c=d"; simple=value',
    ],
)
def test_parse_set_cookie_headers_semicolon_in_quoted_values(header: str) -> None:
    """
    Test that semicolons inside properly quoted values are handled correctly.

    Cookie values can contain semicolons when properly quoted. This test ensures
    that our parser handles these cases correctly, matching SimpleCookie behavior.
    """
    # Test with SimpleCookie
    sc = SimpleCookie()
    sc.load(header)

    # Test with our parser
    result = parse_set_cookie_headers([header])

    # Should parse the same number of cookies
    assert len(result) == len(sc)

    # Verify each cookie matches SimpleCookie
    for (name, morsel), (sc_name, sc_morsel) in zip(result, sc.items()):
        assert name == sc_name
        assert morsel.value == sc_morsel.value


def test_parse_set_cookie_headers_multiple_cookies_same_header() -> None:
    """Test parse_set_cookie_headers with multiple cookies in one header."""
    # Note: SimpleCookie includes the comma as part of the first cookie's value
    headers = ["cookie1=value1, cookie2=value2"]

    result = parse_set_cookie_headers(headers)

    # Should parse as two separate cookies
    assert len(result) == 2
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1,"  # Comma is included in the value
    assert result[1][0] == "cookie2"
    assert result[1][1].value == "value2"


@pytest.mark.parametrize(
    "header",
    [
        # Standard cookies
        "session=abc123",
        "user=john; Path=/",
        "token=xyz; Secure; HttpOnly",
        # Empty values
        "empty=",
        # Quoted values
        'quoted="value with spaces"',
        # Multiple attributes
        "complex=value; Domain=.example.com; Path=/app; Max-Age=3600",
    ],
)
def test_parse_set_cookie_headers_compatibility_with_simple_cookie(header: str) -> None:
    """Test parse_set_cookie_headers is bug-for-bug compatible with SimpleCookie.load."""
    # Parse with SimpleCookie
    sc = SimpleCookie()
    sc.load(header)

    # Parse with our function
    result = parse_set_cookie_headers([header])

    # Should have same number of cookies
    assert len(result) == len(sc)

    # Compare each cookie
    for name, morsel in result:
        assert name in sc
        sc_morsel = sc[name]

        # Compare values
        assert morsel.value == sc_morsel.value
        assert morsel.key == sc_morsel.key

        # Compare attributes (only those that SimpleCookie would set)
        for attr in ["path", "domain", "max-age"]:
            assert morsel.get(attr) == sc_morsel.get(attr)

        # Boolean attributes are handled differently
        # SimpleCookie sets them to empty string when not present, True when present
        for bool_attr in ["secure", "httponly"]:
            # Only check if SimpleCookie has the attribute set to True
            if sc_morsel.get(bool_attr) is True:
                assert morsel.get(bool_attr) is True


def test_parse_set_cookie_headers_relaxed_validation_differences() -> None:
    """Test where parse_set_cookie_headers differs from SimpleCookie (relaxed validation)."""
    # Test cookies that SimpleCookie rejects with CookieError
    rejected_by_simplecookie = [
        ("cookie{with}braces=value1", "cookie{with}braces", "value1"),
        ("cookie(with)parens=value3", "cookie(with)parens", "value3"),
        ("cookie@with@at=value5", "cookie@with@at", "value5"),
    ]

    for header, expected_name, expected_value in rejected_by_simplecookie:
        # SimpleCookie should reject these with CookieError
        sc = SimpleCookie()
        with pytest.raises(CookieError):
            sc.load(header)

        # Our parser should accept them
        result = parse_set_cookie_headers([header])
        assert len(result) == 1  # We accept
        assert result[0][0] == expected_name
        assert result[0][1].value == expected_value

    # Test cookies that SimpleCookie accepts (but we handle more consistently)
    accepted_by_simplecookie = [
        ("cookie[with]brackets=value2", "cookie[with]brackets", "value2"),
        ("cookie:with:colons=value4", "cookie:with:colons", "value4"),
    ]

    for header, expected_name, expected_value in accepted_by_simplecookie:
        # SimpleCookie accepts these
        sc = SimpleCookie()
        sc.load(header)
        # May or may not parse correctly in SimpleCookie

        # Our parser should accept them consistently
        result = parse_set_cookie_headers([header])
        assert len(result) == 1
        assert result[0][0] == expected_name
        assert result[0][1].value == expected_value


def test_parse_set_cookie_headers_case_insensitive_attrs() -> None:
    """Test that known attributes are handled case-insensitively."""
    headers = [
        "cookie1=value1; PATH=/test; DOMAIN=example.com",
        "cookie2=value2; Secure; HTTPONLY; max-AGE=60",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 2

    # First cookie - attributes should be recognized despite case
    assert result[0][1]["path"] == "/test"
    assert result[0][1]["domain"] == "example.com"

    # Second cookie
    assert result[1][1]["secure"] is True
    assert result[1][1]["httponly"] is True
    assert result[1][1]["max-age"] == "60"


def test_parse_set_cookie_headers_unknown_attrs_ignored() -> None:
    """Test that unknown attributes are treated as new cookies (same as SimpleCookie)."""
    headers = [
        "cookie=value; Path=/; unknownattr=ignored; HttpOnly",
    ]

    result = parse_set_cookie_headers(headers)

    # SimpleCookie treats unknown attributes with values as new cookies
    assert len(result) == 2

    # First cookie
    assert result[0][0] == "cookie"
    assert result[0][1]["path"] == "/"
    assert result[0][1]["httponly"] == ""  # Not set on first cookie

    # Second cookie (the unknown attribute)
    assert result[1][0] == "unknownattr"
    assert result[1][1].value == "ignored"
    assert result[1][1]["httponly"] is True  # HttpOnly applies to this cookie


def test_parse_set_cookie_headers_complex_real_world() -> None:
    """Test parse_set_cookie_headers with complex real-world examples."""
    headers = [
        # AWS ELB cookie
        "AWSELB=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890; Path=/",
        # Google Analytics
        "_ga=GA1.2.1234567890.1234567890; Domain=.example.com; Path=/; Expires=Thu, 31-Dec-2025 23:59:59 GMT",
        # Session with all attributes
        "session_id=s%3AabcXYZ123.signature123; Path=/; Secure; HttpOnly; SameSite=Strict",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 3

    # Check each cookie parsed correctly
    assert result[0][0] == "AWSELB"
    assert result[1][0] == "_ga"
    assert result[2][0] == "session_id"

    # Session cookie should have all attributes
    session_morsel = result[2][1]
    assert session_morsel["secure"] is True
    assert session_morsel["httponly"] is True
    assert session_morsel.get("samesite") == "Strict"


def test_parse_set_cookie_headers_boolean_attrs() -> None:
    """Test that boolean attributes (secure, httponly) work correctly."""
    # Test secure attribute variations
    headers = [
        "cookie1=value1; Secure",
        "cookie2=value2; Secure=",
        "cookie3=value3; Secure=true",  # Non-standard but might occur
    ]

    result = parse_set_cookie_headers(headers)
    assert len(result) == 3

    # All should have secure=True
    for name, morsel in result:
        assert morsel.get("secure") is True, f"{name} should have secure=True"

    # Test httponly attribute variations
    headers = [
        "cookie4=value4; HttpOnly",
        "cookie5=value5; HttpOnly=",
    ]

    result = parse_set_cookie_headers(headers)
    assert len(result) == 2

    # All should have httponly=True
    for name, morsel in result:
        assert morsel.get("httponly") is True, f"{name} should have httponly=True"


def test_parse_set_cookie_headers_boolean_attrs_with_partitioned() -> None:
    """Test that boolean attributes including partitioned work correctly."""
    # Test secure attribute variations
    secure_headers = [
        "cookie1=value1; Secure",
        "cookie2=value2; Secure=",
        "cookie3=value3; Secure=true",  # Non-standard but might occur
    ]

    result = parse_set_cookie_headers(secure_headers)
    assert len(result) == 3
    for name, morsel in result:
        assert morsel.get("secure") is True, f"{name} should have secure=True"

    # Test httponly attribute variations
    httponly_headers = [
        "cookie4=value4; HttpOnly",
        "cookie5=value5; HttpOnly=",
    ]

    result = parse_set_cookie_headers(httponly_headers)
    assert len(result) == 2
    for name, morsel in result:
        assert morsel.get("httponly") is True, f"{name} should have httponly=True"

    # Test partitioned attribute variations
    partitioned_headers = [
        "cookie6=value6; Partitioned",
        "cookie7=value7; Partitioned=",
        "cookie8=value8; Partitioned=yes",  # Non-standard but might occur
    ]

    result = parse_set_cookie_headers(partitioned_headers)
    assert len(result) == 3
    for name, morsel in result:
        assert morsel.get("partitioned") is True, f"{name} should have partitioned=True"


def test_parse_set_cookie_headers_encoded_values() -> None:
    """Test that parse_set_cookie_headers preserves encoded values."""
    headers = [
        "encoded=hello%20world",
        "url=https%3A%2F%2Fexample.com%2Fpath",
        "special=%21%40%23%24%25%5E%26*%28%29",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 3
    # Values should be preserved as-is (not decoded)
    assert result[0][1].value == "hello%20world"
    assert result[1][1].value == "https%3A%2F%2Fexample.com%2Fpath"
    assert result[2][1].value == "%21%40%23%24%25%5E%26*%28%29"


def test_parse_set_cookie_headers_partitioned() -> None:
    """
    Test that parse_set_cookie_headers handles partitioned attribute correctly.

    This tests the fix for issue #10380 - partitioned cookies support.
    The partitioned attribute is a boolean flag like secure and httponly.
    """
    headers = [
        "cookie1=value1; Partitioned",
        "cookie2=value2; Partitioned=",
        "cookie3=value3; Partitioned=true",  # Non-standard but might occur
        "cookie4=value4; Secure; Partitioned; HttpOnly",
        "cookie5=value5; Domain=.example.com; Path=/; Partitioned",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 5

    # All cookies should have partitioned=True
    for i, (name, morsel) in enumerate(result):
        assert (
            morsel.get("partitioned") is True
        ), f"Cookie {i+1} should have partitioned=True"
        assert name == f"cookie{i+1}"
        assert morsel.value == f"value{i+1}"

    # Cookie 4 should also have secure and httponly
    assert result[3][1].get("secure") is True
    assert result[3][1].get("httponly") is True

    # Cookie 5 should also have domain and path
    assert result[4][1].get("domain") == ".example.com"
    assert result[4][1].get("path") == "/"


def test_parse_set_cookie_headers_partitioned_case_insensitive() -> None:
    """Test that partitioned attribute is recognized case-insensitively."""
    headers = [
        "cookie1=value1; partitioned",  # lowercase
        "cookie2=value2; PARTITIONED",  # uppercase
        "cookie3=value3; Partitioned",  # title case
        "cookie4=value4; PaRtItIoNeD",  # mixed case
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 4

    # All should be recognized as partitioned
    for i, (_, morsel) in enumerate(result):
        assert (
            morsel.get("partitioned") is True
        ), f"Cookie {i+1} should have partitioned=True"


def test_parse_set_cookie_headers_partitioned_not_set() -> None:
    """Test that cookies without partitioned attribute don't have it set."""
    headers = [
        "normal=value; Secure; HttpOnly",
        "regular=cookie; Path=/",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 2

    # Check that partitioned is not set (empty string is the default for flags in Morsel)
    assert result[0][1].get("partitioned", "") == ""
    assert result[1][1].get("partitioned", "") == ""


# Tests that don't require partitioned support in SimpleCookie
def test_parse_set_cookie_headers_partitioned_with_other_attrs_manual() -> None:
    """
    Test parsing logic for partitioned cookies combined with all other attributes.

    This test verifies our parsing logic handles partitioned correctly as a boolean
    attribute regardless of SimpleCookie support.
    """
    # Test that our parser recognizes partitioned in _COOKIE_KNOWN_ATTRS and _COOKIE_BOOL_ATTRS
    assert "partitioned" in helpers._COOKIE_KNOWN_ATTRS
    assert "partitioned" in helpers._COOKIE_BOOL_ATTRS

    # Test a simple case that won't trigger SimpleCookie errors
    headers = ["session=abc123; Secure; HttpOnly"]
    result = parse_set_cookie_headers(headers)

    assert len(result) == 1
    assert result[0][0] == "session"
    assert result[0][1]["secure"] is True
    assert result[0][1]["httponly"] is True


def test_cookie_helpers_constants_include_partitioned() -> None:
    """Test that cookie helper constants include partitioned attribute."""
    # Test our constants include partitioned
    assert "partitioned" in helpers._COOKIE_KNOWN_ATTRS
    assert "partitioned" in helpers._COOKIE_BOOL_ATTRS


@pytest.mark.parametrize(
    "test_string",
    [
        " Partitioned ",
        " partitioned ",
        " PARTITIONED ",
        " Partitioned; ",
        " Partitioned= ",
        " Partitioned=true ",
    ],
)
def test_cookie_pattern_matches_partitioned_attribute(test_string: str) -> None:
    """Test that the cookie pattern regex matches various partitioned attribute formats."""
    pattern = helpers._COOKIE_PATTERN
    match = pattern.match(test_string)
    assert match is not None, f"Pattern should match '{test_string}'"
    assert match.group("key").lower() == "partitioned"


def test_parse_set_cookie_headers_issue_7993_double_quotes() -> None:
    """
    Test that cookies with unmatched opening quotes don't break parsing of subsequent cookies.

    This reproduces issue #7993 where a cookie containing an unmatched opening double quote
    causes subsequent cookies to be silently dropped.
    NOTE: This only fixes the specific case where a value starts with a quote but doesn't
    end with one (e.g., 'cookie="value'). Other malformed quote cases still behave like
    SimpleCookie for compatibility.
    """
    # Test case from the issue
    headers = ['foo=bar; baz="qux; foo2=bar2']

    result = parse_set_cookie_headers(headers)

    # Should parse all cookies correctly
    assert len(result) == 3
    assert result[0][0] == "foo"
    assert result[0][1].value == "bar"
    assert result[1][0] == "baz"
    assert result[1][1].value == '"qux'  # Unmatched quote included
    assert result[2][0] == "foo2"
    assert result[2][1].value == "bar2"


def test_parse_set_cookie_headers_empty_headers() -> None:
    """Test handling of empty headers in the sequence."""
    # Empty header should be skipped
    result = parse_set_cookie_headers(["", "name=value"])
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1].value == "value"

    # Multiple empty headers
    result = parse_set_cookie_headers(["", "", ""])
    assert result == []

    # Empty headers mixed with valid cookies
    result = parse_set_cookie_headers(["", "a=1", "", "b=2", ""])
    assert len(result) == 2
    assert result[0][0] == "a"
    assert result[1][0] == "b"


def test_parse_set_cookie_headers_invalid_cookie_syntax() -> None:
    """Test handling of invalid cookie syntax."""
    # No valid cookie pattern
    result = parse_set_cookie_headers(["@#$%^&*()"])
    assert result == []

    # Cookie name without value
    result = parse_set_cookie_headers(["name"])
    assert result == []

    # Multiple invalid patterns
    result = parse_set_cookie_headers(["!!!!", "????", "name", "@@@"])
    assert result == []


def test_parse_set_cookie_headers_illegal_cookie_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Test that illegal cookie names are rejected.

    Note: When a known attribute name is used as a cookie name at the start,
    parsing stops early (before any warning can be logged). Warnings are only
    logged when illegal names appear after a valid cookie.
    """
    # Cookie name that is a known attribute (illegal) - parsing stops early
    result = parse_set_cookie_headers(["path=value; domain=test"])
    assert result == []

    # Cookie name that doesn't match the pattern
    result = parse_set_cookie_headers(["=value"])
    assert result == []

    # Valid cookie after illegal one - parsing stops at illegal
    result = parse_set_cookie_headers(["domain=bad; good=value"])
    assert result == []

    # Illegal cookie name that appears after a valid cookie triggers warning
    result = parse_set_cookie_headers(["good=value; Path=/; invalid,cookie=value;"])
    assert len(result) == 1
    assert result[0][0] == "good"
    assert "Illegal cookie name 'invalid,cookie'" in caplog.text


def test_parse_set_cookie_headers_attributes_before_cookie() -> None:
    """Test that attributes before any cookie are invalid."""
    # Path attribute before cookie
    result = parse_set_cookie_headers(["Path=/; name=value"])
    assert result == []

    # Domain attribute before cookie
    result = parse_set_cookie_headers(["Domain=.example.com; name=value"])
    assert result == []

    # Multiple attributes before cookie
    result = parse_set_cookie_headers(
        ["Path=/; Domain=.example.com; Secure; name=value"]
    )
    assert result == []


def test_parse_set_cookie_headers_attributes_without_values() -> None:
    """Test handling of attributes with missing values."""
    # Boolean attribute without value (valid)
    result = parse_set_cookie_headers(["name=value; Secure"])
    assert len(result) == 1
    assert result[0][1]["secure"] is True

    # Non-boolean attribute without value (invalid, stops parsing)
    result = parse_set_cookie_headers(["name=value; Path"])
    assert len(result) == 1
    # Path without value stops further attribute parsing

    # Multiple cookies, invalid attribute in middle
    result = parse_set_cookie_headers(["name=value; Path; Secure"])
    assert len(result) == 1
    # Secure is not parsed because Path without value stops parsing


def test_parse_set_cookie_headers_dollar_prefixed_names() -> None:
    """Test handling of cookie names starting with $."""
    # $Version without preceding cookie (ignored)
    result = parse_set_cookie_headers(["$Version=1; name=value"])
    assert len(result) == 1
    assert result[0][0] == "name"

    # Multiple $ prefixed without cookie (all ignored)
    result = parse_set_cookie_headers(["$Version=1; $Path=/; $Domain=.com; name=value"])
    assert len(result) == 1
    assert result[0][0] == "name"

    # $ prefix at start is ignored, cookie follows
    result = parse_set_cookie_headers(["$Unknown=123; valid=cookie"])
    assert len(result) == 1
    assert result[0][0] == "valid"


def test_parse_set_cookie_headers_dollar_attributes() -> None:
    """Test handling of $ prefixed attributes after cookies."""
    # Test multiple $ attributes with cookie (case-insensitive like SimpleCookie)
    result = parse_set_cookie_headers(["name=value; $Path=/test; $Domain=.example.com"])
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1]["path"] == "/test"
    assert result[0][1]["domain"] == ".example.com"

    # Test unknown $ attribute (should be ignored)
    result = parse_set_cookie_headers(["name=value; $Unknown=test"])
    assert len(result) == 1
    assert result[0][0] == "name"
    # $Unknown should not be set

    # Test $ attribute with empty value
    result = parse_set_cookie_headers(["name=value; $Path="])
    assert len(result) == 1
    assert result[0][1]["path"] == ""

    # Test case sensitivity compatibility with SimpleCookie
    result = parse_set_cookie_headers(["test=value; $path=/lower; $PATH=/upper"])
    assert len(result) == 1
    # Last one wins, and it's case-insensitive
    assert result[0][1]["path"] == "/upper"


def test_parse_set_cookie_headers_attributes_after_illegal_cookie() -> None:
    """
    Test that attributes after an illegal cookie name are handled correctly.

    This covers the branches where current_morsel is None because an illegal
    cookie name was encountered.
    """
    # Illegal cookie followed by $ attribute
    result = parse_set_cookie_headers(["good=value; invalid,cookie=bad; $Path=/test"])
    assert len(result) == 1
    assert result[0][0] == "good"
    # $Path should be ignored since current_morsel is None after illegal cookie

    # Illegal cookie followed by boolean attribute
    result = parse_set_cookie_headers(["good=value; invalid,cookie=bad; HttpOnly"])
    assert len(result) == 1
    assert result[0][0] == "good"
    # HttpOnly should be ignored since current_morsel is None

    # Illegal cookie followed by regular attribute with value
    result = parse_set_cookie_headers(["good=value; invalid,cookie=bad; Max-Age=3600"])
    assert len(result) == 1
    assert result[0][0] == "good"
    # Max-Age should be ignored since current_morsel is None

    # Multiple attributes after illegal cookie
    result = parse_set_cookie_headers(
        ["good=value; invalid,cookie=bad; $Path=/; HttpOnly; Max-Age=60; Domain=.com"]
    )
    assert len(result) == 1
    assert result[0][0] == "good"
    # All attributes should be ignored after illegal cookie


def test_parse_set_cookie_headers_unmatched_quotes_compatibility() -> None:
    """
    Test that most unmatched quote scenarios behave like SimpleCookie.

    For compatibility, we only handle the specific case of unmatched opening quotes
    (e.g., 'cookie="value'). Other cases behave the same as SimpleCookie.
    """
    # Cases that SimpleCookie and our parser both fail to parse completely
    incompatible_cases = [
        'cookie1=val"ue; cookie2=value2',  # codespell:ignore
        'cookie1=value"; cookie2=value2',
        'cookie1=va"l"ue"; cookie2=value2',  # codespell:ignore
        'cookie1=value1; cookie2=val"ue; cookie3=value3',  # codespell:ignore
    ]

    for header in incompatible_cases:
        # Test SimpleCookie behavior
        sc = SimpleCookie()
        sc.load(header)
        sc_cookies = list(sc.items())

        # Test our parser behavior
        result = parse_set_cookie_headers([header])

        # Both should parse the same cookies (partial parsing)
        assert len(result) == len(sc_cookies), (
            f"Header: {header}\n"
            f"SimpleCookie parsed: {len(sc_cookies)} cookies\n"
            f"Our parser parsed: {len(result)} cookies"
        )

    # The case we specifically fix (unmatched opening quote)
    fixed_case = 'cookie1=value1; cookie2="unmatched; cookie3=value3'

    # SimpleCookie fails to parse cookie3
    sc = SimpleCookie()
    sc.load(fixed_case)
    assert len(sc) == 1  # Only cookie1

    # Our parser handles it better
    result = parse_set_cookie_headers([fixed_case])
    assert len(result) == 3  # All three cookies
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1"
    assert result[1][0] == "cookie2"
    assert result[1][1].value == '"unmatched'
    assert result[2][0] == "cookie3"
    assert result[2][1].value == "value3"


def test_parse_set_cookie_headers_expires_attribute() -> None:
    """Test parse_set_cookie_headers handles expires attribute with date formats."""
    headers = [
        "session=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
        "user=xyz; expires=Wednesday, 09-Jun-21 10:18:14 GMT",
        "token=123; EXPIRES=Wed, 09 Jun 2021 10:18:14 GMT",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 3
    for _, morsel in result:
        assert "expires" in morsel
        assert "GMT" in morsel["expires"]


def test_parse_set_cookie_headers_edge_cases() -> None:
    """Test various edge cases."""
    # Very long cookie values
    long_value = "x" * 4096
    result = parse_set_cookie_headers([f"name={long_value}"])
    assert len(result) == 1
    assert result[0][1].value == long_value


def test_parse_set_cookie_headers_various_date_formats_issue_4327() -> None:
    """
    Test that parse_set_cookie_headers handles various date formats per RFC 6265.

    This tests the fix for issue #4327 - support for RFC 822, RFC 850,
    and ANSI C asctime() date formats in cookie expiration.
    """
    # Test various date formats
    headers = [
        # RFC 822 format (preferred format)
        "cookie1=value1; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
        # RFC 850 format (obsolete but still used)
        "cookie2=value2; Expires=Wednesday, 09-Jun-21 10:18:14 GMT",
        # RFC 822 with dashes
        "cookie3=value3; Expires=Wed, 09-Jun-2021 10:18:14 GMT",
        # ANSI C asctime() format (aiohttp extension - not supported by SimpleCookie)
        "cookie4=value4; Expires=Wed Jun  9 10:18:14 2021",
        # Various other formats seen in the wild
        "cookie5=value5; Expires=Thu, 01 Jan 2030 00:00:00 GMT",
        "cookie6=value6; Expires=Mon, 31-Dec-99 23:59:59 GMT",
        "cookie7=value7; Expires=Tue, 01-Jan-30 00:00:00 GMT",
    ]

    result = parse_set_cookie_headers(headers)

    # All cookies should be parsed
    assert len(result) == 7

    # Check each cookie was parsed with its expires attribute
    expected_cookies = [
        ("cookie1", "value1", "Wed, 09 Jun 2021 10:18:14 GMT"),
        ("cookie2", "value2", "Wednesday, 09-Jun-21 10:18:14 GMT"),
        ("cookie3", "value3", "Wed, 09-Jun-2021 10:18:14 GMT"),
        ("cookie4", "value4", "Wed Jun  9 10:18:14 2021"),
        ("cookie5", "value5", "Thu, 01 Jan 2030 00:00:00 GMT"),
        ("cookie6", "value6", "Mon, 31-Dec-99 23:59:59 GMT"),
        ("cookie7", "value7", "Tue, 01-Jan-30 00:00:00 GMT"),
    ]

    for (name, morsel), (exp_name, exp_value, exp_expires) in zip(
        result, expected_cookies
    ):
        assert name == exp_name
        assert morsel.value == exp_value
        assert morsel.get("expires") == exp_expires


def test_parse_set_cookie_headers_ansi_c_asctime_format() -> None:
    """
    Test parsing of ANSI C asctime() format.

    This tests support for ANSI C asctime() format (e.g., "Wed Jun  9 10:18:14 2021").
    NOTE: This is an aiohttp extension - SimpleCookie does NOT support this format.
    """
    headers = ["cookie1=value1; Expires=Wed Jun  9 10:18:14 2021"]

    result = parse_set_cookie_headers(headers)

    # Should parse correctly with the expires attribute preserved
    assert len(result) == 1
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1"
    assert result[0][1]["expires"] == "Wed Jun  9 10:18:14 2021"


def test_parse_set_cookie_headers_rfc2822_timezone_issue_4493() -> None:
    """
    Test that parse_set_cookie_headers handles RFC 2822 timezone formats.

    This tests the fix for issue #4493 - support for RFC 2822-compliant dates
    with timezone offsets like -0000, +0100, etc.
    NOTE: This is an aiohttp extension - SimpleCookie does NOT support this format.
    """
    headers = [
        # RFC 2822 with -0000 timezone (common in some APIs)
        "hello=world; expires=Wed, 15 Jan 2020 09:45:07 -0000",
        # RFC 2822 with positive offset
        "session=abc123; expires=Thu, 01 Feb 2024 14:30:00 +0100",
        # RFC 2822 with negative offset
        "token=xyz789; expires=Fri, 02 Mar 2025 08:15:30 -0500",
        # Standard GMT for comparison
        "classic=cookie; expires=Sat, 03 Apr 2026 12:00:00 GMT",
    ]

    result = parse_set_cookie_headers(headers)

    # All cookies should be parsed
    assert len(result) == 4

    # Check each cookie was parsed with its expires attribute
    assert result[0][0] == "hello"
    assert result[0][1].value == "world"
    assert result[0][1]["expires"] == "Wed, 15 Jan 2020 09:45:07 -0000"

    assert result[1][0] == "session"
    assert result[1][1].value == "abc123"
    assert result[1][1]["expires"] == "Thu, 01 Feb 2024 14:30:00 +0100"

    assert result[2][0] == "token"
    assert result[2][1].value == "xyz789"
    assert result[2][1]["expires"] == "Fri, 02 Mar 2025 08:15:30 -0500"

    assert result[3][0] == "classic"
    assert result[3][1].value == "cookie"
    assert result[3][1]["expires"] == "Sat, 03 Apr 2026 12:00:00 GMT"


def test_parse_set_cookie_headers_rfc2822_with_attributes() -> None:
    """Test that RFC 2822 dates work correctly with other cookie attributes."""
    headers = [
        "session=abc123; expires=Wed, 15 Jan 2020 09:45:07 -0000; Path=/; HttpOnly; Secure",
        "token=xyz789; expires=Thu, 01 Feb 2024 14:30:00 +0100; Domain=.example.com; SameSite=Strict",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 2

    # First cookie
    assert result[0][0] == "session"
    assert result[0][1].value == "abc123"
    assert result[0][1]["expires"] == "Wed, 15 Jan 2020 09:45:07 -0000"
    assert result[0][1]["path"] == "/"
    assert result[0][1]["httponly"] is True
    assert result[0][1]["secure"] is True

    # Second cookie
    assert result[1][0] == "token"
    assert result[1][1].value == "xyz789"
    assert result[1][1]["expires"] == "Thu, 01 Feb 2024 14:30:00 +0100"
    assert result[1][1]["domain"] == ".example.com"
    assert result[1][1]["samesite"] == "Strict"


def test_parse_set_cookie_headers_date_formats_with_attributes() -> None:
    """Test that date formats work correctly with other cookie attributes."""
    headers = [
        "session=abc123; Expires=Wed, 09 Jun 2030 10:18:14 GMT; Path=/; HttpOnly; Secure",
        "token=xyz789; Expires=Wednesday, 09-Jun-30 10:18:14 GMT; Domain=.example.com; SameSite=Strict",
    ]

    result = parse_set_cookie_headers(headers)

    assert len(result) == 2

    # First cookie
    assert result[0][0] == "session"
    assert result[0][1].value == "abc123"
    assert result[0][1]["expires"] == "Wed, 09 Jun 2030 10:18:14 GMT"
    assert result[0][1]["path"] == "/"
    assert result[0][1]["httponly"] is True
    assert result[0][1]["secure"] is True

    # Second cookie
    assert result[1][0] == "token"
    assert result[1][1].value == "xyz789"
    assert result[1][1]["expires"] == "Wednesday, 09-Jun-30 10:18:14 GMT"
    assert result[1][1]["domain"] == ".example.com"
    assert result[1][1]["samesite"] == "Strict"


@pytest.mark.parametrize(
    ("header", "expected_name", "expected_value", "expected_coded"),
    [
        # Test cookie values with octal escape sequences
        (r'name="\012newline\012"', "name", "\nnewline\n", r'"\012newline\012"'),
        (
            r'tab="\011separated\011values"',
            "tab",
            "\tseparated\tvalues",
            r'"\011separated\011values"',
        ),
        (
            r'mixed="hello\040world\041"',
            "mixed",
            "hello world!",
            r'"hello\040world\041"',
        ),
        (
            r'complex="\042quoted\042 text with \012 newline"',
            "complex",
            '"quoted" text with \n newline',
            r'"\042quoted\042 text with \012 newline"',
        ),
    ],
)
def test_parse_set_cookie_headers_uses_unquote_with_octal(
    header: str, expected_name: str, expected_value: str, expected_coded: str
) -> None:
    """Test that parse_set_cookie_headers correctly unquotes values with octal sequences and preserves coded_value."""
    result = parse_set_cookie_headers([header])

    assert len(result) == 1
    name, morsel = result[0]

    # Check that octal sequences were properly decoded in the value
    assert name == expected_name
    assert morsel.value == expected_value

    # Check that coded_value preserves the original quoted string
    assert morsel.coded_value == expected_coded


# Tests for parse_cookie_header (RFC 6265 compliant Cookie header parser)


def test_parse_cookie_header_simple() -> None:
    """Test parse_cookie_header with simple cookies."""
    header = "name=value; session=abc123"

    result = parse_cookie_header(header)

    assert len(result) == 2
    assert result[0][0] == "name"
    assert result[0][1].value == "value"
    assert result[1][0] == "session"
    assert result[1][1].value == "abc123"


def test_parse_cookie_header_empty() -> None:
    """Test parse_cookie_header with empty header."""
    assert parse_cookie_header("") == []
    assert parse_cookie_header("   ") == []


def test_parse_cookie_header_quoted_values() -> None:
    """Test parse_cookie_header handles quoted values correctly."""
    header = 'name="quoted value"; session="with;semicolon"; data="with\\"escaped\\""'

    result = parse_cookie_header(header)

    assert len(result) == 3
    assert result[0][0] == "name"
    assert result[0][1].value == "quoted value"
    assert result[1][0] == "session"
    assert result[1][1].value == "with;semicolon"
    assert result[2][0] == "data"
    assert result[2][1].value == 'with"escaped"'


def test_parse_cookie_header_special_chars() -> None:
    """Test parse_cookie_header accepts special characters in names."""
    header = (
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}=value1; cookie[index]=value2"
    )

    result = parse_cookie_header(header)

    assert len(result) == 2
    assert result[0][0] == "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}"
    assert result[0][1].value == "value1"
    assert result[1][0] == "cookie[index]"
    assert result[1][1].value == "value2"


def test_parse_cookie_header_invalid_names() -> None:
    """Test parse_cookie_header rejects invalid cookie names."""
    # Invalid names with control characters
    header = "invalid\tcookie=value; valid=cookie; invalid\ncookie=bad"

    result = parse_cookie_header(header)

    # Parse_cookie_header uses same regex as parse_set_cookie_headers
    # Tab and newline are treated as separators, not part of names
    assert len(result) == 5
    assert result[0][0] == "invalid"
    assert result[0][1].value == ""
    assert result[1][0] == "cookie"
    assert result[1][1].value == "value"
    assert result[2][0] == "valid"
    assert result[2][1].value == "cookie"
    assert result[3][0] == "invalid"
    assert result[3][1].value == ""
    assert result[4][0] == "cookie"
    assert result[4][1].value == "bad"


def test_parse_cookie_header_no_attributes() -> None:
    """Test parse_cookie_header treats all pairs as cookies (no attributes)."""
    # In Cookie headers, even reserved attribute names are treated as cookies
    header = (
        "session=abc123; path=/test; domain=.example.com; secure=yes; httponly=true"
    )

    result = parse_cookie_header(header)

    assert len(result) == 5
    assert result[0][0] == "session"
    assert result[0][1].value == "abc123"
    assert result[1][0] == "path"
    assert result[1][1].value == "/test"
    assert result[2][0] == "domain"
    assert result[2][1].value == ".example.com"
    assert result[3][0] == "secure"
    assert result[3][1].value == "yes"
    assert result[4][0] == "httponly"
    assert result[4][1].value == "true"


def test_parse_cookie_header_empty_value() -> None:
    """Test parse_cookie_header with empty cookie values."""
    header = "empty=; name=value; also_empty="

    result = parse_cookie_header(header)

    assert len(result) == 3
    assert result[0][0] == "empty"
    assert result[0][1].value == ""
    assert result[1][0] == "name"
    assert result[1][1].value == "value"
    assert result[2][0] == "also_empty"
    assert result[2][1].value == ""


def test_parse_cookie_header_spaces() -> None:
    """Test parse_cookie_header handles spaces correctly."""
    header = "name1=value1 ;  name2=value2  ; name3=value3"

    result = parse_cookie_header(header)

    assert len(result) == 3
    assert result[0][0] == "name1"
    assert result[0][1].value == "value1"
    assert result[1][0] == "name2"
    assert result[1][1].value == "value2"
    assert result[2][0] == "name3"
    assert result[2][1].value == "value3"


def test_parse_cookie_header_encoded_values() -> None:
    """Test parse_cookie_header preserves encoded values."""
    header = "encoded=hello%20world; url=https%3A%2F%2Fexample.com"

    result = parse_cookie_header(header)

    assert len(result) == 2
    assert result[0][0] == "encoded"
    assert result[0][1].value == "hello%20world"
    assert result[1][0] == "url"
    assert result[1][1].value == "https%3A%2F%2Fexample.com"


def test_parse_cookie_header_malformed() -> None:
    """Test parse_cookie_header handles malformed input."""
    # Missing value
    header = "name1=value1; justname; name2=value2"

    result = parse_cookie_header(header)

    # Parser accepts cookies without values (empty value)
    assert len(result) == 3
    assert result[0][0] == "name1"
    assert result[0][1].value == "value1"
    assert result[1][0] == "justname"
    assert result[1][1].value == ""
    assert result[2][0] == "name2"
    assert result[2][1].value == "value2"

    # Missing name
    header = "=value; name=value2"
    result = parse_cookie_header(header)
    assert len(result) == 2
    assert result[0][0] == "=value"
    assert result[0][1].value == ""
    assert result[1][0] == "name"
    assert result[1][1].value == "value2"


def test_parse_cookie_header_complex_quoted() -> None:
    """Test parse_cookie_header with complex quoted values."""
    header = 'session="abc;xyz"; data="value;with;multiple;semicolons"; simple=unquoted'

    result = parse_cookie_header(header)

    assert len(result) == 3
    assert result[0][0] == "session"
    assert result[0][1].value == "abc;xyz"
    assert result[1][0] == "data"
    assert result[1][1].value == "value;with;multiple;semicolons"
    assert result[2][0] == "simple"
    assert result[2][1].value == "unquoted"


def test_parse_cookie_header_unmatched_quotes() -> None:
    """Test parse_cookie_header handles unmatched quotes."""
    header = 'cookie1=value1; cookie2="unmatched; cookie3=value3'

    result = parse_cookie_header(header)

    # Should parse all cookies correctly
    assert len(result) == 3
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1"
    assert result[1][0] == "cookie2"
    assert result[1][1].value == '"unmatched'
    assert result[2][0] == "cookie3"
    assert result[2][1].value == "value3"


def test_parse_cookie_header_vs_parse_set_cookie_headers() -> None:
    """Test difference between parse_cookie_header and parse_set_cookie_headers."""
    # Cookie header with attribute-like pairs
    cookie_header = "session=abc123; path=/test; secure=yes"

    # parse_cookie_header treats all as cookies
    cookie_result = parse_cookie_header(cookie_header)
    assert len(cookie_result) == 3
    assert cookie_result[0][0] == "session"
    assert cookie_result[0][1].value == "abc123"
    assert cookie_result[1][0] == "path"
    assert cookie_result[1][1].value == "/test"
    assert cookie_result[2][0] == "secure"
    assert cookie_result[2][1].value == "yes"

    # parse_set_cookie_headers would treat path and secure as attributes
    set_cookie_result = parse_set_cookie_headers([cookie_header])
    assert len(set_cookie_result) == 1
    assert set_cookie_result[0][0] == "session"
    assert set_cookie_result[0][1].value == "abc123"
    assert set_cookie_result[0][1]["path"] == "/test"
    # secure with any value is treated as boolean True
    assert set_cookie_result[0][1]["secure"] is True


def test_parse_cookie_header_compatibility_with_simple_cookie() -> None:
    """Test parse_cookie_header output works with SimpleCookie."""
    header = "session=abc123; user=john; token=xyz789"

    # Parse with our function
    parsed = parse_cookie_header(header)

    # Create SimpleCookie and update with our results
    sc = SimpleCookie()
    sc.update(parsed)

    # Verify all cookies are present
    assert len(sc) == 3
    assert sc["session"].value == "abc123"
    assert sc["user"].value == "john"
    assert sc["token"].value == "xyz789"


def test_parse_cookie_header_real_world_examples() -> None:
    """Test parse_cookie_header with real-world Cookie headers."""
    # Google Analytics style
    header = "_ga=GA1.2.1234567890.1234567890; _gid=GA1.2.0987654321.0987654321"
    result = parse_cookie_header(header)
    assert len(result) == 2
    assert result[0][0] == "_ga"
    assert result[0][1].value == "GA1.2.1234567890.1234567890"
    assert result[1][0] == "_gid"
    assert result[1][1].value == "GA1.2.0987654321.0987654321"

    # Session cookies
    header = "PHPSESSID=abc123def456; csrf_token=xyz789; logged_in=true"
    result = parse_cookie_header(header)
    assert len(result) == 3
    assert result[0][0] == "PHPSESSID"
    assert result[0][1].value == "abc123def456"
    assert result[1][0] == "csrf_token"
    assert result[1][1].value == "xyz789"
    assert result[2][0] == "logged_in"
    assert result[2][1].value == "true"

    # Complex values with proper quoting
    header = r'preferences="{\"theme\":\"dark\",\"lang\":\"en\"}"; session_data=eyJhbGciOiJIUzI1NiJ9'
    result = parse_cookie_header(header)
    assert len(result) == 2
    assert result[0][0] == "preferences"
    assert result[0][1].value == '{"theme":"dark","lang":"en"}'
    assert result[1][0] == "session_data"
    assert result[1][1].value == "eyJhbGciOiJIUzI1NiJ9"


def test_parse_cookie_header_issue_7993() -> None:
    """Test parse_cookie_header handles issue #7993 correctly."""
    # This specific case from issue #7993
    header = 'foo=bar; baz="qux; foo2=bar2'

    result = parse_cookie_header(header)

    # All cookies should be parsed
    assert len(result) == 3
    assert result[0][0] == "foo"
    assert result[0][1].value == "bar"
    assert result[1][0] == "baz"
    assert result[1][1].value == '"qux'
    assert result[2][0] == "foo2"
    assert result[2][1].value == "bar2"


def test_parse_cookie_header_illegal_names(caplog: pytest.LogCaptureFixture) -> None:
    """Test parse_cookie_header warns about illegal cookie names."""
    # Cookie name with comma (not allowed in _COOKIE_NAME_RE)
    header = "good=value; invalid,cookie=bad; another=test"
    result = parse_cookie_header(header)
    # Should skip the invalid cookie but continue parsing
    assert len(result) == 2
    assert result[0][0] == "good"
    assert result[0][1].value == "value"
    assert result[1][0] == "another"
    assert result[1][1].value == "test"
    assert "Can not load cookie: Illegal cookie name 'invalid,cookie'" in caplog.text


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Unquoted strings should remain unchanged
        ("simple", "simple"),
        ("with spaces", "with spaces"),
        ("", ""),
        ('"', '"'),  # String too short to be quoted
        ('some"text', 'some"text'),  # Quotes not at beginning/end
        ('text"with"quotes', 'text"with"quotes'),
    ],
)
def test_unquote_basic(input_str: str, expected: str) -> None:
    """Test basic _unquote functionality."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Basic quoted strings
        ('"quoted"', "quoted"),
        ('"with spaces"', "with spaces"),
        ('""', ""),  # Empty quoted string
        # Quoted string with special characters
        ('"hello, world!"', "hello, world!"),
        ('"path=/test"', "path=/test"),
    ],
)
def test_unquote_quoted_strings(input_str: str, expected: str) -> None:
    """Test _unquote with quoted strings."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Escaped quotes should be unescaped
        (r'"say \"hello\""', 'say "hello"'),
        (r'"nested \"quotes\" here"', 'nested "quotes" here'),
        # Multiple escaped quotes
        (r'"\"start\" middle \"end\""', '"start" middle "end"'),
    ],
)
def test_unquote_escaped_quotes(input_str: str, expected: str) -> None:
    """Test _unquote with escaped quotes."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Single escaped backslash
        (r'"path\\to\\file"', "path\\to\\file"),
        # Backslash before quote
        (r'"end with slash\\"', "end with slash\\"),
        # Mixed escaped characters
        (r'"path\\to\\\"file\""', 'path\\to\\"file"'),
    ],
)
def test_unquote_escaped_backslashes(input_str: str, expected: str) -> None:
    """Test _unquote with escaped backslashes."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Common octal sequences
        (r'"\012"', "\n"),  # newline
        (r'"\011"', "\t"),  # tab
        (r'"\015"', "\r"),  # carriage return
        (r'"\040"', " "),  # space
        # Octal sequences in context
        (r'"line1\012line2"', "line1\nline2"),
        (r'"tab\011separated"', "tab\tseparated"),
        # Multiple octal sequences
        (r'"\012\011\015"', "\n\t\r"),
        # Mixed octal and regular text
        (r'"hello\040world\041"', "hello world!"),
    ],
)
def test_unquote_octal_sequences(input_str: str, expected: str) -> None:
    """Test _unquote with octal escape sequences."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Test boundary values
        (r'"\000"', "\x00"),  # null character
        (r'"\001"', "\x01"),
        (r'"\177"', "\x7f"),  # DEL character
        (r'"\200"', "\x80"),  # Extended ASCII
        (r'"\377"', "\xff"),  # Max octal value
        # Invalid octal sequences (not 3 digits or > 377) are treated as regular escapes
        (r'"\400"', "400"),  # 400 octal = 256 decimal, too large
        (r'"\777"', "777"),  # 777 octal = 511 decimal, too large
    ],
)
def test_unquote_octal_full_range(input_str: str, expected: str) -> None:
    """Test _unquote with full range of valid octal sequences."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # Mix of quotes, backslashes, and octal
        (r'"say \"hello\"\012new line"', 'say "hello"\nnew line'),
        (r'"path\\to\\file\011\011data"', "path\\to\\file\t\tdata"),
        # Complex mixed example
        (r'"\042quoted\042 and \134backslash\134"', '"quoted" and \\backslash\\'),
        # Escaped characters that aren't special
        (r'"\a\b\c"', "abc"),  # \a, \b, \c -> a, b, c
    ],
)
def test_unquote_mixed_escapes(input_str: str, expected: str) -> None:
    """Test _unquote with mixed escape sequences."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # String that starts with quote but doesn't end with one
        ('"not closed', '"not closed'),
        # String that ends with quote but doesn't start with one
        ('not opened"', 'not opened"'),
        # Multiple quotes
        ('"""', '"'),
        ('""""', '""'),
        # Backslash at the end without anything to escape
        (r'"ends with\"', "ends with\\"),
        # Empty escape
        (r'"test\"', "test\\"),
        # Just escaped characters
        (r'"\"\"\""', '"""'),
    ],
)
def test_unquote_edge_cases(input_str: str, expected: str) -> None:
    """Test _unquote edge cases."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    ("input_str", "expected"),
    [
        # JSON-like data
        (r'"{\"user\":\"john\",\"id\":123}"', '{"user":"john","id":123}'),
        # URL-encoded then quoted
        ('"hello%20world"', "hello%20world"),
        # Path with backslashes (Windows-style)
        (r'"C:\\Users\\John\\Documents"', "C:\\Users\\John\\Documents"),
        # Complex session data
        (
            r'"session_data=\"user123\";expires=2024"',
            'session_data="user123";expires=2024',
        ),
    ],
)
def test_unquote_real_world_examples(input_str: str, expected: str) -> None:
    """Test _unquote with real-world cookie value examples."""
    assert _unquote(input_str) == expected


@pytest.mark.parametrize(
    "test_value",
    [
        '""',
        '"simple"',
        r'"with \"quotes\""',
        r'"with \\backslash\\"',
        r'"\012newline"',
        r'"complex\042quote\134slash\012"',
        '"not-quoted',
        'also-not-quoted"',
        r'"mixed\011\042\134test"',
    ],
)
def test_unquote_compatibility_with_simplecookie(test_value: str) -> None:
    """Test that _unquote behaves like SimpleCookie's unquoting."""
    assert _unquote(test_value) == simplecookie_unquote(test_value), (
        f"Mismatch for {test_value!r}: "
        f"our={_unquote(test_value)!r}, "
        f"SimpleCookie={simplecookie_unquote(test_value)!r}"
    )
