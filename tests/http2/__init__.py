import pytest

# skip all HTTP/2 tests if hpack is not available
pytest.importorskip("hpack")
