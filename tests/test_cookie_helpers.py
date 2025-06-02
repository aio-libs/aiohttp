"""Tests for internal cookie helper functions."""

from http.cookies import CookieError, Morsel, SimpleCookie
from unittest import mock

import pytest

from aiohttp import _cookie_helpers as helpers
from aiohttp._cookie_helpers import (
    make_non_quoted_morsel,
    make_quoted_morsel,
    parse_cookie_headers,
    preserve_morsel_with_coded_value,
)

# ------------------- Cookie parsing tests ----------------------------------


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


def test_parse_cookie_headers_simple() -> None:
    """Test parse_cookie_headers with simple cookies."""
    headers = ["name=value", "session=abc123"]

    result = parse_cookie_headers(headers)

    assert len(result) == 2
    assert result[0][0] == "name"
    assert result[0][1].key == "name"
    assert result[0][1].value == "value"
    assert result[1][0] == "session"
    assert result[1][1].key == "session"
    assert result[1][1].value == "abc123"


def test_parse_cookie_headers_with_attributes() -> None:
    """Test parse_cookie_headers with cookie attributes."""
    headers = [
        "sessionid=value123; Path=/; HttpOnly; Secure",
        "user=john; Domain=.example.com; Max-Age=3600",
    ]

    result = parse_cookie_headers(headers)

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


def test_parse_cookie_headers_special_chars_in_names() -> None:
    """Test parse_cookie_headers accepts special characters in names (#2683)."""
    # These should be accepted with relaxed validation
    headers = [
        "ISAWPLB{A7F52349-3531-4DA9-8776-F74BC6F4F1BB}=value1",
        "cookie[index]=value2",
        "cookie(param)=value3",
        "cookie:name=value4",
        "cookie@domain=value5",
    ]

    result = parse_cookie_headers(headers)

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


def test_parse_cookie_headers_invalid_names() -> None:
    """Test parse_cookie_headers rejects truly invalid cookie names."""
    # These should be rejected even with relaxed validation
    headers = [
        "invalid\tcookie=value",  # Tab character
        "invalid\ncookie=value",  # Newline
        "invalid\rcookie=value",  # Carriage return
        "\x00badname=value",  # Null character
        "name with spaces=value",  # Spaces in name
    ]

    result = parse_cookie_headers(headers)

    # All should be skipped
    assert len(result) == 0


def test_parse_cookie_headers_empty_and_invalid() -> None:
    """Test parse_cookie_headers handles empty and invalid formats."""
    headers = [
        "",  # Empty header
        "   ",  # Whitespace only
        "=value",  # No name
        "name=",  # Empty value (should be accepted)
        "justname",  # No value (should be skipped)
        "path=/",  # Reserved attribute as name (should be skipped)
        "Domain=.com",  # Reserved attribute as name (should be skipped)
    ]

    result = parse_cookie_headers(headers)

    # Only "name=" should be accepted
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1].value == ""


def test_parse_cookie_headers_quoted_values() -> None:
    """Test parse_cookie_headers handles quoted values correctly."""
    headers = [
        'name="quoted value"',
        'session="with;semicolon"',
        'data="with\\"escaped\\""',
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3
    assert result[0][1].value == "quoted value"
    assert result[1][1].value == "with;semicolon"
    assert result[2][1].value == 'with"escaped"'


def test_parse_cookie_headers_semicolon_in_quoted_values() -> None:
    """
    Test that semicolons inside properly quoted values are handled correctly.

    Cookie values can contain semicolons when properly quoted. This test ensures
    that our parser handles these cases correctly, matching SimpleCookie behavior.
    """
    # Test various cases of semicolons in quoted values
    headers = [
        'session="abc;xyz"; token=123',
        'data="value;with;multiple;semicolons"; next=cookie',
        'complex="a=b;c=d"; simple=value',
    ]

    for header in headers:
        # Test with SimpleCookie
        sc = SimpleCookie()
        sc.load(header)

        # Test with our parser
        result = parse_cookie_headers([header])

        # Should parse the same number of cookies
        assert len(result) == len(sc)

        # Verify each cookie matches SimpleCookie
        for (name, morsel), (sc_name, sc_morsel) in zip(result, sc.items()):
            assert name == sc_name
            assert morsel.value == sc_morsel.value


def test_parse_cookie_headers_multiple_cookies_same_header() -> None:
    """Test parse_cookie_headers with multiple cookies in one header."""
    # Note: SimpleCookie includes the comma as part of the first cookie's value
    headers = ["cookie1=value1, cookie2=value2"]

    result = parse_cookie_headers(headers)

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
def test_parse_cookie_headers_compatibility_with_simple_cookie(header: str) -> None:
    """Test parse_cookie_headers is bug-for-bug compatible with SimpleCookie.load."""
    # Parse with SimpleCookie
    sc = SimpleCookie()
    sc.load(header)

    # Parse with our function
    result = parse_cookie_headers([header])

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


def test_parse_cookie_headers_relaxed_validation_differences() -> None:
    """Test where parse_cookie_headers differs from SimpleCookie (relaxed validation)."""
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
        result = parse_cookie_headers([header])
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
        result = parse_cookie_headers([header])
        assert len(result) == 1
        assert result[0][0] == expected_name
        assert result[0][1].value == expected_value


def test_parse_cookie_headers_case_insensitive_attrs() -> None:
    """Test that known attributes are handled case-insensitively."""
    headers = [
        "cookie1=value1; PATH=/test; DOMAIN=example.com",
        "cookie2=value2; Secure; HTTPONLY; max-AGE=60",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 2

    # First cookie - attributes should be recognized despite case
    assert result[0][1]["path"] == "/test"
    assert result[0][1]["domain"] == "example.com"

    # Second cookie
    assert result[1][1]["secure"] is True
    assert result[1][1]["httponly"] is True
    assert result[1][1]["max-age"] == "60"


def test_parse_cookie_headers_unknown_attrs_ignored() -> None:
    """Test that unknown attributes are treated as new cookies (same as SimpleCookie)."""
    headers = [
        "cookie=value; Path=/; unknownattr=ignored; HttpOnly",
    ]

    result = parse_cookie_headers(headers)

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


def test_parse_cookie_headers_complex_real_world() -> None:
    """Test parse_cookie_headers with complex real-world examples."""
    headers = [
        # AWS ELB cookie
        "AWSELB=ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890; Path=/",
        # Google Analytics
        "_ga=GA1.2.1234567890.1234567890; Domain=.example.com; Path=/; Expires=Thu, 31-Dec-2025 23:59:59 GMT",
        # Session with all attributes
        "session_id=s%3AabcXYZ123.signature123; Path=/; Secure; HttpOnly; SameSite=Strict",
    ]

    result = parse_cookie_headers(headers)

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


def test_parse_cookie_headers_boolean_attrs() -> None:
    """Test that boolean attributes (secure, httponly) work correctly."""
    # Test secure attribute variations
    headers = [
        "cookie1=value1; Secure",
        "cookie2=value2; Secure=",
        "cookie3=value3; Secure=true",  # Non-standard but might occur
    ]

    result = parse_cookie_headers(headers)
    assert len(result) == 3

    # All should have secure=True
    for name, morsel in result:
        assert morsel.get("secure") is True, f"{name} should have secure=True"

    # Test httponly attribute variations
    headers = [
        "cookie4=value4; HttpOnly",
        "cookie5=value5; HttpOnly=",
    ]

    result = parse_cookie_headers(headers)
    assert len(result) == 2

    # All should have httponly=True
    for name, morsel in result:
        assert morsel.get("httponly") is True, f"{name} should have httponly=True"


def test_parse_cookie_headers_boolean_attrs_with_partitioned() -> None:
    """Test that boolean attributes including partitioned work correctly."""
    # Create patched reserved and flags with partitioned support
    patched_reserved = Morsel._reserved.copy()  # type: ignore[attr-defined]
    patched_reserved["partitioned"] = "partitioned"

    patched_flags = Morsel._flags.copy()  # type: ignore[attr-defined]
    patched_flags.add("partitioned")

    with (
        mock.patch.object(Morsel, "_reserved", patched_reserved),
        mock.patch.object(Morsel, "_flags", patched_flags),
    ):
        # Test secure attribute variations
        secure_headers = [
            "cookie1=value1; Secure",
            "cookie2=value2; Secure=",
            "cookie3=value3; Secure=true",  # Non-standard but might occur
        ]

        result = parse_cookie_headers(secure_headers)
        assert len(result) == 3
        for name, morsel in result:
            assert morsel.get("secure") is True, f"{name} should have secure=True"

        # Test httponly attribute variations
        httponly_headers = [
            "cookie4=value4; HttpOnly",
            "cookie5=value5; HttpOnly=",
        ]

        result = parse_cookie_headers(httponly_headers)
        assert len(result) == 2
        for name, morsel in result:
            assert morsel.get("httponly") is True, f"{name} should have httponly=True"

        # Test partitioned attribute variations
        partitioned_headers = [
            "cookie6=value6; Partitioned",
            "cookie7=value7; Partitioned=",
            "cookie8=value8; Partitioned=yes",  # Non-standard but might occur
        ]

        result = parse_cookie_headers(partitioned_headers)
        assert len(result) == 3
        for name, morsel in result:
            assert (
                morsel.get("partitioned") is True
            ), f"{name} should have partitioned=True"


def test_parse_cookie_headers_encoded_values() -> None:
    """Test that parse_cookie_headers preserves encoded values."""
    headers = [
        "encoded=hello%20world",
        "url=https%3A%2F%2Fexample.com%2Fpath",
        "special=%21%40%23%24%25%5E%26*%28%29",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3
    # Values should be preserved as-is (not decoded)
    assert result[0][1].value == "hello%20world"
    assert result[1][1].value == "https%3A%2F%2Fexample.com%2Fpath"
    assert result[2][1].value == "%21%40%23%24%25%5E%26*%28%29"


def test_parse_cookie_headers_partitioned() -> None:
    """
    Test that parse_cookie_headers handles partitioned attribute correctly.

    This tests the fix for issue #10380 - partitioned cookies support.
    The partitioned attribute is a boolean flag like secure and httponly.
    On Python < 3.14, this test demonstrates that aiohttp's parser can handle
    partitioned cookies even though Python's SimpleCookie doesn't natively support them.
    """
    # Create patched reserved and flags with partitioned support
    patched_reserved = Morsel._reserved.copy()  # type: ignore[attr-defined]
    patched_reserved["partitioned"] = "partitioned"

    patched_flags = Morsel._flags.copy()  # type: ignore[attr-defined]
    patched_flags.add("partitioned")

    with (
        mock.patch.object(Morsel, "_reserved", patched_reserved),
        mock.patch.object(Morsel, "_flags", patched_flags),
    ):

        headers = [
            "cookie1=value1; Partitioned",
            "cookie2=value2; Partitioned=",
            "cookie3=value3; Partitioned=true",  # Non-standard but might occur
            "cookie4=value4; Secure; Partitioned; HttpOnly",
            "cookie5=value5; Domain=.example.com; Path=/; Partitioned",
        ]

        result = parse_cookie_headers(headers)

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


def test_parse_cookie_headers_partitioned_case_insensitive() -> None:
    """Test that partitioned attribute is recognized case-insensitively."""
    # Create patched reserved and flags with partitioned support
    patched_reserved = Morsel._reserved.copy()  # type: ignore[attr-defined]
    patched_reserved["partitioned"] = "partitioned"

    patched_flags = Morsel._flags.copy()  # type: ignore[attr-defined]
    patched_flags.add("partitioned")

    with (
        mock.patch.object(Morsel, "_reserved", patched_reserved),
        mock.patch.object(Morsel, "_flags", patched_flags),
    ):

        headers = [
            "cookie1=value1; partitioned",  # lowercase
            "cookie2=value2; PARTITIONED",  # uppercase
            "cookie3=value3; Partitioned",  # title case
            "cookie4=value4; PaRtItIoNeD",  # mixed case
        ]

        result = parse_cookie_headers(headers)

        assert len(result) == 4

        # All should be recognized as partitioned
        for i, (_, morsel) in enumerate(result):
            assert (
                morsel.get("partitioned") is True
            ), f"Cookie {i+1} should have partitioned=True"


def test_parse_cookie_headers_partitioned_not_set() -> None:
    """Test that cookies without partitioned attribute don't have it set."""
    headers = [
        "normal=value; Secure; HttpOnly",
        "regular=cookie; Path=/",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 2

    # Check that partitioned is not set (empty string is the default for flags in Morsel)
    assert result[0][1].get("partitioned", "") == ""
    assert result[1][1].get("partitioned", "") == ""


# Tests that don't require partitioned support in SimpleCookie
def test_parse_cookie_headers_partitioned_with_other_attrs_manual() -> None:
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
    result = parse_cookie_headers(headers)

    assert len(result) == 1
    assert result[0][0] == "session"
    assert result[0][1]["secure"] is True
    assert result[0][1]["httponly"] is True


def test_parse_cookie_headers_partitioned_real_world_structure() -> None:
    """
    Test real-world partitioned cookie structure without using SimpleCookie.

    This verifies our parsing logic correctly identifies partitioned as a known
    boolean attribute.
    """
    # Test our constants include partitioned
    assert "partitioned" in helpers._COOKIE_KNOWN_ATTRS
    assert "partitioned" in helpers._COOKIE_BOOL_ATTRS

    # Verify the pattern would match partitioned attributes
    pattern = helpers._COOKIE_PATTERN

    # Test various partitioned formats
    test_strings = [
        " Partitioned ",
        " partitioned ",
        " PARTITIONED ",
        " Partitioned; ",
        " Partitioned= ",
        " Partitioned=true ",
    ]

    for test_str in test_strings:
        match = pattern.match(test_str)
        assert match is not None, f"Pattern should match '{test_str}'"
        assert match.group("key").lower() == "partitioned"


def test_parse_cookie_headers_issue_7993_double_quotes() -> None:
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

    result = parse_cookie_headers(headers)

    # Should parse all cookies correctly
    assert len(result) == 3
    assert result[0][0] == "foo"
    assert result[0][1].value == "bar"
    assert result[1][0] == "baz"
    assert result[1][1].value == '"qux'  # Unmatched quote included
    assert result[2][0] == "foo2"
    assert result[2][1].value == "bar2"


def test_parse_cookie_headers_empty_headers() -> None:
    """Test handling of empty headers in the sequence."""
    # Empty header should be skipped
    result = parse_cookie_headers(["", "name=value"])
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1].value == "value"

    # Multiple empty headers
    result = parse_cookie_headers(["", "", ""])
    assert result == []

    # Empty headers mixed with valid cookies
    result = parse_cookie_headers(["", "a=1", "", "b=2", ""])
    assert len(result) == 2
    assert result[0][0] == "a"
    assert result[1][0] == "b"


def test_parse_cookie_headers_invalid_cookie_syntax() -> None:
    """Test handling of invalid cookie syntax."""
    # No valid cookie pattern
    result = parse_cookie_headers(["@#$%^&*()"])
    assert result == []

    # Cookie name without value
    result = parse_cookie_headers(["name"])
    assert result == []

    # Multiple invalid patterns
    result = parse_cookie_headers(["!!!!", "????", "name", "@@@"])
    assert result == []


def test_parse_cookie_headers_illegal_cookie_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Test that illegal cookie names are rejected.

    Note: When a known attribute name is used as a cookie name at the start,
    parsing stops early (before any warning can be logged). Warnings are only
    logged when illegal names appear after a valid cookie.
    """
    # Cookie name that is a known attribute (illegal) - parsing stops early
    result = parse_cookie_headers(["path=value; domain=test"])
    assert result == []

    # Cookie name that doesn't match the pattern
    result = parse_cookie_headers(["=value"])
    assert result == []

    # Valid cookie after illegal one - parsing stops at illegal
    result = parse_cookie_headers(["domain=bad; good=value"])
    assert result == []

    # Illegal cookie name that appears after a valid cookie triggers warning
    result = parse_cookie_headers(["good=value; Path=/; invalid,cookie=value;"])
    assert len(result) == 1
    assert result[0][0] == "good"
    assert "Illegal cookie name 'invalid,cookie'" in caplog.text


def test_parse_cookie_headers_attributes_before_cookie() -> None:
    """Test that attributes before any cookie are invalid."""
    # Path attribute before cookie
    result = parse_cookie_headers(["Path=/; name=value"])
    assert result == []

    # Domain attribute before cookie
    result = parse_cookie_headers(["Domain=.example.com; name=value"])
    assert result == []

    # Multiple attributes before cookie
    result = parse_cookie_headers(["Path=/; Domain=.example.com; Secure; name=value"])
    assert result == []


def test_parse_cookie_headers_attributes_without_values() -> None:
    """Test handling of attributes with missing values."""
    # Boolean attribute without value (valid)
    result = parse_cookie_headers(["name=value; Secure"])
    assert len(result) == 1
    assert result[0][1]["secure"] is True

    # Non-boolean attribute without value (invalid, stops parsing)
    result = parse_cookie_headers(["name=value; Path"])
    assert len(result) == 1
    # Path without value stops further attribute parsing

    # Multiple cookies, invalid attribute in middle
    result = parse_cookie_headers(["name=value; Path; Secure"])
    assert len(result) == 1
    # Secure is not parsed because Path without value stops parsing


def test_parse_cookie_headers_dollar_prefixed_names() -> None:
    """Test handling of cookie names starting with $."""
    # $Version without preceding cookie (ignored)
    result = parse_cookie_headers(["$Version=1; name=value"])
    assert len(result) == 1
    assert result[0][0] == "name"

    # Multiple $ prefixed without cookie (all ignored)
    result = parse_cookie_headers(["$Version=1; $Path=/; $Domain=.com; name=value"])
    assert len(result) == 1
    assert result[0][0] == "name"

    # $ prefix at start is ignored, cookie follows
    result = parse_cookie_headers(["$Unknown=123; valid=cookie"])
    assert len(result) == 1
    assert result[0][0] == "valid"


def test_parse_cookie_headers_dollar_attributes() -> None:
    """Test handling of $ prefixed attributes after cookies."""
    # Test multiple $ attributes with cookie (case-insensitive like SimpleCookie)
    result = parse_cookie_headers(["name=value; $Path=/test; $Domain=.example.com"])
    assert len(result) == 1
    assert result[0][0] == "name"
    assert result[0][1]["path"] == "/test"
    assert result[0][1]["domain"] == ".example.com"

    # Test unknown $ attribute (should be ignored)
    result = parse_cookie_headers(["name=value; $Unknown=test"])
    assert len(result) == 1
    assert result[0][0] == "name"
    # $Unknown should not be set

    # Test $ attribute with empty value
    result = parse_cookie_headers(["name=value; $Path="])
    assert len(result) == 1
    assert result[0][1]["path"] == ""

    # Test case sensitivity compatibility with SimpleCookie
    result = parse_cookie_headers(["test=value; $path=/lower; $PATH=/upper"])
    assert len(result) == 1
    # Last one wins, and it's case-insensitive
    assert result[0][1]["path"] == "/upper"


def test_parse_cookie_headers_attributes_after_illegal_cookie() -> None:
    """
    Test that attributes after an illegal cookie name are handled correctly.

    This covers the branches where current_morsel is None because an illegal
    cookie name was encountered.
    """
    # Illegal cookie followed by $ attribute
    result = parse_cookie_headers(["good=value; invalid,cookie=bad; $Path=/test"])
    assert len(result) == 1
    assert result[0][0] == "good"
    # $Path should be ignored since current_morsel is None after illegal cookie

    # Illegal cookie followed by boolean attribute
    result = parse_cookie_headers(["good=value; invalid,cookie=bad; HttpOnly"])
    assert len(result) == 1
    assert result[0][0] == "good"
    # HttpOnly should be ignored since current_morsel is None

    # Illegal cookie followed by regular attribute with value
    result = parse_cookie_headers(["good=value; invalid,cookie=bad; Max-Age=3600"])
    assert len(result) == 1
    assert result[0][0] == "good"
    # Max-Age should be ignored since current_morsel is None

    # Multiple attributes after illegal cookie
    result = parse_cookie_headers(
        ["good=value; invalid,cookie=bad; $Path=/; HttpOnly; Max-Age=60; Domain=.com"]
    )
    assert len(result) == 1
    assert result[0][0] == "good"
    # All attributes should be ignored after illegal cookie


def test_parse_cookie_headers_unmatched_quotes_compatibility() -> None:
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
        result = parse_cookie_headers([header])

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
    result = parse_cookie_headers([fixed_case])
    assert len(result) == 3  # All three cookies
    assert result[0][0] == "cookie1"
    assert result[0][1].value == "value1"
    assert result[1][0] == "cookie2"
    assert result[1][1].value == '"unmatched'
    assert result[2][0] == "cookie3"
    assert result[2][1].value == "value3"


def test_parse_cookie_headers_expires_attribute() -> None:
    """Test parse_cookie_headers handles expires attribute with date formats."""
    headers = [
        "session=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
        "user=xyz; expires=Wednesday, 09-Jun-21 10:18:14 GMT",
        "token=123; EXPIRES=Wed, 09 Jun 2021 10:18:14 GMT",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3
    for _, morsel in result:
        assert "expires" in morsel
        assert "GMT" in morsel["expires"]


def test_make_non_quoted_morsel() -> None:
    """Test make_non_quoted_morsel creates unquoted morsels."""
    # Create a source morsel with a value that would normally be quoted
    source = Morsel()
    source.set("test", "value with spaces", "value%20with%20spaces")

    # Make non-quoted version
    result = make_non_quoted_morsel(source)

    assert result.key == "test"
    assert result.value == "value with spaces"
    # coded_value should be same as value (no quotes)
    assert result.coded_value == "value with spaces"
    assert result is not source  # Should be a new instance


def test_make_quoted_morsel() -> None:
    """Test make_quoted_morsel creates properly quoted morsels."""
    # Create a source morsel with a value that needs quoting
    source = Morsel()
    source.set("test", "value with spaces", "ignored_coded_value")

    # Make quoted version
    result = make_quoted_morsel(source)

    assert result.key == "test"
    assert result.value == "value with spaces"
    # coded_value should be quoted
    assert result.coded_value == '"value with spaces"'
    assert result is not source  # Should be a new instance


def test_make_quoted_morsel_special_chars() -> None:
    """Test make_quoted_morsel handles special characters correctly."""
    # Test various special characters that require quoting
    # SimpleCookie.value_encode escapes some characters but not others
    test_cases = [
        ("semicolon", "value;with;semicolon", '"value\\073with\\073semicolon"'),
        ("comma", "value,with,comma", '"value\\054with\\054comma"'),
        ("space", "value with space", '"value with space"'),
        ("equals", "value=with=equals", '"value=with=equals"'),  # equals is not escaped
    ]

    for name, value, expected_coded in test_cases:
        source = Morsel()
        source.set(name, value, "ignored")

        result = make_quoted_morsel(source)

        assert result.key == name
        assert result.value == value
        assert result.coded_value == expected_coded


def test_morsel_helper_functions_integration() -> None:
    """Test integration of all morsel helper functions."""
    # Create a cookie with special characters
    original = Morsel()
    original.set("session", "abc;123", '"abc\\073123"')

    # Test making non-quoted version
    non_quoted = make_non_quoted_morsel(original)
    assert non_quoted.coded_value == "abc;123"  # No quotes

    # Test making quoted version
    quoted = make_quoted_morsel(original)
    assert quoted.coded_value == '"abc\\073123"'  # With quotes and escaped semicolon
