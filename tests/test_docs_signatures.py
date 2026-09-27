"""Guards against API reference signatures drifting away from the code.

The reference manuals spell out signatures in ``.. class::`` / ``.. function::`` /
``.. method::`` directives. When a parameter is renamed or a default changes, the
prose is easy to miss, and readers end up copying a call that raises ``TypeError``.
These tests compare the documented signature against the real object.
"""

import inspect
import re
from pathlib import Path
from typing import Any

from aiohttp import ClientTimeout, FormData, web
from aiohttp.compression_utils import MAX_SYNC_CHUNK_SIZE
from aiohttp.multipart import BodyPartReader

DOCS = Path(__file__).parent.parent / "docs"


def documented_signature(stem: str, directive: str, name: str) -> str:
    """Return the documented signature of *name* in a reST directive."""
    text = (DOCS / stem).read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^[ \t]*\.\. {re.escape(directive)}:: {re.escape(name)}\((.*?)\)\s*$",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    assert match is not None, f"{name} not documented in {stem}"
    # reST wraps long signatures with a trailing backslash on each continued line.
    raw = match.group(1).replace("\\\n", "")
    return re.sub(r"\s+", "", raw)


def test_run_app_documents_keepalive_timeout_default() -> None:
    signature = documented_signature("web_reference.rst", "function", "run_app")
    default = inspect.signature(web.run_app).parameters["keepalive_timeout"].default
    assert f"keepalive_timeout={default}" in signature
    assert "keepalive_timeout=3630" not in signature


def test_response_documents_zlib_executor_size_default() -> None:
    signature = documented_signature("web_reference.rst", "class", "Response")
    default = inspect.signature(web.Response).parameters["zlib_executor_size"].default
    assert f"zlib_executor_size={default}" in signature
    assert default == MAX_SYNC_CHUNK_SIZE


def test_get_charset_default_is_required() -> None:
    signature = documented_signature("multipart_reference.rst", "method", "get_charset")
    assert signature == "default"
    parameter = inspect.signature(BodyPartReader.get_charset).parameters["default"]
    assert parameter.default is inspect.Parameter.empty


def test_add_field_documents_no_removed_parameter() -> None:
    signature = documented_signature("client_reference.rst", "method", "add_field")
    assert signature == "name,value,*,content_type=None,filename=None"
    parameters = inspect.signature(FormData.add_field).parameters
    assert "content_transfer_encoding" not in parameters
    for name in ("content_type", "filename"):
        assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY


def test_client_timeout_documents_ceil_threshold() -> None:
    signature = documented_signature("client_reference.rst", "class", "ClientTimeout")
    assert "ceil_threshold=5" in signature
    assert ClientTimeout().ceil_threshold == 5


def test_documented_signatures_have_no_unknown_parameters() -> None:
    """Every parameter named in the docs must exist on the real callable."""
    cases: list[tuple[str, str, str, Any]] = [
        ("client_reference.rst", "class", "ClientTimeout", ClientTimeout),
        ("web_reference.rst", "class", "Response", web.Response),
        ("web_reference.rst", "function", "run_app", web.run_app),
    ]
    for stem, directive, name, obj in cases:
        signature = documented_signature(stem, directive, name)
        documented = {
            part.split("=")[0].lstrip("*")
            for part in signature.split(",")
            if part and part != "*"
        }
        actual = set(inspect.signature(obj).parameters)
        assert (
            documented <= actual
        ), f"{name} in {stem} documents unknown parameters: {documented - actual}"
