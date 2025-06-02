"""Tests for internal cookie helper functions."""

from http.cookies import CookieError, Morsel, SimpleCookie

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
    """Test that semicolons inside properly quoted values are handled correctly.

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
        # SimpleCookie should accept these (though it may warn)
        sc = SimpleCookie()
        try:
            sc.load(header)
            # If successful, verify our parser matches
            result = parse_cookie_headers([header])
            assert len(result) == 1
            assert result[0][0] == expected_name
            assert result[0][1].value == expected_value
        except CookieError:
            # If SimpleCookie rejects it, we should still accept it
            result = parse_cookie_headers([header])
            assert len(result) == 1
            assert result[0][0] == expected_name
            assert result[0][1].value == expected_value


def test_parse_cookie_headers_dollar_prefix() -> None:
    """Test parse_cookie_headers handles $ prefixed attributes."""
    headers = [
        "$Version=1; session=abc123; $Path=/app",
        "user=john; $Domain=.example.com",
    ]

    result = parse_cookie_headers(headers)

    # $ prefixed attributes should be associated with previous cookie
    assert len(result) == 2
    assert result[0][0] == "session"
    assert result[0][1].value == "abc123"
    assert result[0][1]["path"] == "/app"
    assert result[1][0] == "user"
    assert result[1][1].value == "john"
    assert result[1][1]["domain"] == ".example.com"


def test_parse_cookie_headers_attribute_before_cookie() -> None:
    """Test parse_cookie_headers handles invalid order (attribute before cookie)."""
    headers = [
        "Path=/; session=abc123",  # Invalid: attribute before cookie
        "Secure; token=xyz",  # Invalid: attribute before cookie
    ]

    result = parse_cookie_headers(headers)

    # Should skip the invalid parts and parse nothing
    assert len(result) == 0


def test_parse_cookie_headers_multiple_equals() -> None:
    """Test parse_cookie_headers handles values with = signs."""
    headers = [
        "data=key=value",
        "encoded=base64==",
        "formula=a=b+c",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3
    assert result[0][1].value == "key=value"
    assert result[1][1].value == "base64=="
    assert result[2][1].value == "a=b+c"


def test_parse_cookie_headers_case_sensitivity() -> None:
    """Test parse_cookie_headers handles case sensitivity correctly."""
    headers = [
        "session=abc123; PATH=/app; DOMAIN=.example.com; SECURE",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 1
    morsel = result[0][1]
    assert morsel["path"] == "/app"  # Attributes are case-insensitive
    assert morsel["domain"] == ".example.com"
    assert morsel["secure"] is True


def test_parse_cookie_headers_real_world_examples() -> None:
    """Test parse_cookie_headers with real-world cookie examples."""
    # Examples from various web services
    headers = [
        # Google Analytics
        "_ga=GA1.2.1234567890.1234567890; Path=/; Domain=.example.com",
        # AWS ALB
        "AWSALB=abcdefghijklmnop; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/",
        # Session cookie with all attributes
        "session_id=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/app",
    ]

    result = parse_cookie_headers(headers)

    assert len(result) == 3

    # Google Analytics cookie
    ga_cookie = result[0][1]
    assert ga_cookie.key == "_ga"
    assert ga_cookie.value == "GA1.2.1234567890.1234567890"
    assert ga_cookie["path"] == "/"
    assert ga_cookie["domain"] == ".example.com"

    # AWS ALB cookie
    alb_cookie = result[1][1]
    assert alb_cookie.key == "AWSALB"
    assert alb_cookie.value == "abcdefghijklmnop"
    assert alb_cookie["expires"] == "Wed, 09 Jun 2021 10:18:14 GMT"
    assert alb_cookie["path"] == "/"

    # Session cookie
    session_cookie = result[2][1]
    assert session_cookie.key == "session_id"
    assert session_cookie.value == "abc123xyz"
    assert session_cookie["secure"] is True
    assert session_cookie["httponly"] is True
    assert session_cookie["samesite"] == "Strict"
    assert session_cookie["path"] == "/app"


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
    test_cases = [
        ("semicolon", "value;with;semicolon", '"value;with;semicolon"'),
        ("comma", "value,with,comma", '"value,with,comma"'),
        ("space", "value with space", '"value with space"'),
        ("equals", "value=with=equals", '"value=with=equals"'),
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
    original.set("session", "abc;123", '"abc;123"')

    # Test preserving coded_value
    preserved = preserve_morsel_with_coded_value(original)
    assert preserved.coded_value == '"abc;123"'

    # Test making non-quoted version
    non_quoted = make_non_quoted_morsel(original)
    assert non_quoted.coded_value == "abc;123"  # No quotes

    # Test making quoted version
    quoted = make_quoted_morsel(original)
    assert quoted.coded_value == '"abc;123"'  # With quotes
