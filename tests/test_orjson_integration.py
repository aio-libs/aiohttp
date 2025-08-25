"""Tests for orjson integration in aiohttp."""

import json
import sys
from typing import Any, Optional
from unittest.mock import Mock, patch

import pytest

from aiohttp import JsonPayload, typedefs, web
from aiohttp.client import ClientSession
from aiohttp.test_utils import AiohttpClient


# Mock orjson functions for testing
def mock_orjson_dumps(data: Any, *, option: Optional[int] = None) -> bytes:
    """Mock orjson.dumps function that returns bytes."""
    # Add some unique marker to distinguish from json.dumps
    result = {"_orjson_used": True, "data": data}
    return json.dumps(result).encode("utf-8")


def mock_orjson_loads(data: bytes) -> Any:
    """Mock orjson.loads function that accepts bytes."""
    decoded = json.loads(data.decode("utf-8"))
    if decoded.get("_orjson_used"):
        return decoded["data"]
    return decoded


class TestOrjsonIntegration:
    """Test orjson integration for JSON serialization."""

    def test_default_json_encoder_uses_orjson_when_available(self) -> None:
        """Test that DEFAULT_JSON_ENCODER uses orjson when available."""
        with patch.dict(sys.modules, {"orjson": Mock()}):
            # Mock orjson module
            orjson_mock = sys.modules["orjson"]
            orjson_mock.dumps = mock_orjson_dumps
            orjson_mock.OPT_NAIVE_UTC = 1  # Mock option constant
            orjson_mock.OPT_OMIT_MICROSECONDS = 2

            # Reload typedefs to pick up orjson
            import importlib

            importlib.reload(typedefs)

            # Test that orjson is used
            test_data = {"test": "data", "number": 42}
            result = typedefs.DEFAULT_JSON_ENCODER(test_data)

            # Should return string (our mock converts bytes to string)
            assert isinstance(result, str)
            parsed_result = json.loads(result)
            assert parsed_result["_orjson_used"] is True
            assert parsed_result["data"] == test_data

    def test_default_json_encoder_fallback_to_json_dumps(self) -> None:
        """Test that DEFAULT_JSON_ENCODER falls back to json.dumps when orjson unavailable."""
        # Ensure orjson is not available
        with patch.dict(sys.modules, {"orjson": None}):
            import importlib

            importlib.reload(typedefs)

            # Test that json.dumps is used
            test_data = {"test": "data", "number": 42}
            result = typedefs.DEFAULT_JSON_ENCODER(test_data)

            # Should return same as json.dumps
            assert result == json.dumps(test_data)
            # Should not have orjson marker
            assert "_orjson_used" not in result

    def test_json_payload_uses_default_encoder_by_default(self) -> None:
        """Test that JsonPayload uses DEFAULT_JSON_ENCODER by default."""
        with patch.dict(sys.modules, {"orjson": Mock()}):
            orjson_mock = sys.modules["orjson"]
            orjson_mock.dumps = mock_orjson_dumps
            orjson_mock.OPT_NAIVE_UTC = 1
            orjson_mock.OPT_OMIT_MICROSECONDS = 2

            import importlib

            importlib.reload(typedefs)

            test_data = {"test": "payload_data"}
            payload = JsonPayload(test_data)

            # The payload should use orjson internally
            assert payload.content_type == "application/json"

            # Check the actual serialized data contains orjson marker
            data = payload._value
            assert isinstance(data, bytes)
            parsed = json.loads(data.decode("utf-8"))
            assert parsed["_orjson_used"] is True
            assert parsed["data"] == test_data

    def test_json_payload_can_override_encoder(self) -> None:
        """Test that JsonPayload can still use custom encoder when provided."""

        def custom_encoder(obj: Any) -> str:
            return json.dumps({"custom": True, "data": obj})

        test_data = {"test": "custom_data"}
        payload = JsonPayload(test_data, dumps=custom_encoder)

        # Should use custom encoder, not orjson
        data = payload._value
        assert isinstance(data, bytes)
        parsed = json.loads(data.decode("utf-8"))
        assert parsed["custom"] is True
        assert parsed["data"] == test_data
        assert "_orjson_used" not in parsed

    async def test_client_session_uses_default_encoder_by_default(self) -> None:
        """Test that ClientSession uses DEFAULT_JSON_ENCODER by default."""
        with patch.dict(sys.modules, {"orjson": Mock()}):
            orjson_mock = sys.modules["orjson"]
            orjson_mock.dumps = mock_orjson_dumps
            orjson_mock.OPT_NAIVE_UTC = 1
            orjson_mock.OPT_OMIT_MICROSECONDS = 2

            import importlib

            importlib.reload(typedefs)

            async with ClientSession() as session:
                # Verify the session uses DEFAULT_JSON_ENCODER
                assert session._json_serialize is typedefs.DEFAULT_JSON_ENCODER

    async def test_client_session_can_override_encoder(self) -> None:
        """Test that ClientSession can use custom JSON encoder when provided."""

        def custom_encoder(obj: Any) -> str:
            return json.dumps({"session_custom": True, "data": obj})

        async with ClientSession(json_serialize=custom_encoder) as session:
            # Verify the session uses custom encoder
            assert session._json_serialize is custom_encoder

            # Test actual usage
            result = session._json_serialize({"test": "data"})
            parsed = json.loads(result)
            assert parsed["session_custom"] is True
            assert parsed["data"] == {"test": "data"}

    async def test_client_session_json_request_with_orjson(
        self, aiohttp_client: AiohttpClient
    ) -> None:
        """Test client session JSON requests work with orjson."""
        with patch.dict(sys.modules, {"orjson": Mock()}):
            orjson_mock = sys.modules["orjson"]
            orjson_mock.dumps = mock_orjson_dumps
            orjson_mock.loads = mock_orjson_loads
            orjson_mock.OPT_NAIVE_UTC = 1
            orjson_mock.OPT_OMIT_MICROSECONDS = 2

            import importlib

            importlib.reload(typedefs)

            received_data = None

            async def handler(request: web.Request) -> web.Response:
                nonlocal received_data
                received_data = await request.json()
                return web.Response(text="OK")

            app = web.Application()
            app.router.add_post("/", handler)
            client = await aiohttp_client(app)

            test_data = {"test": "json_request", "number": 123}

            # Make request with JSON data
            async with client.post("/", json=test_data) as resp:
                assert resp.status == 200

            # Verify the data was received correctly
            # Since we use orjson mock, the received data should be the original
            assert received_data == test_data

    async def test_json_payload_with_fallback_when_orjson_unavailable(self) -> None:
        """Test JsonPayload works with json.dumps when orjson is not available."""
        # Ensure orjson is not available
        with patch.dict(sys.modules, {"orjson": None}):
            import importlib

            importlib.reload(typedefs)

            test_data = {"fallback": "test", "works": True}
            payload = JsonPayload(test_data)

            # Should still work with json.dumps
            assert payload.content_type == "application/json"

            # Check the serialized data
            data = payload._value
            assert isinstance(data, bytes)
            parsed = json.loads(data.decode("utf-8"))
            assert parsed == test_data
            assert "_orjson_used" not in str(data)

    def test_orjson_handles_datetime_serialization(self) -> None:
        """Test that orjson integration handles datetime objects properly."""
        from datetime import datetime

        with patch.dict(sys.modules, {"orjson": Mock()}):
            orjson_mock = sys.modules["orjson"]

            def orjson_dumps_with_datetime(
                data: Any, *, option: Optional[int] = None
            ) -> bytes:
                """Mock orjson.dumps that handles datetime."""
                if isinstance(data, dict):
                    # Convert datetime to string for JSON serialization
                    serializable_data = {}
                    for k, v in data.items():
                        if isinstance(v, datetime):
                            serializable_data[k] = v.isoformat()
                        else:
                            serializable_data[k] = v
                    result = {"_orjson_used": True, "data": serializable_data}
                else:
                    result = {"_orjson_used": True, "data": data}
                return json.dumps(result).encode("utf-8")

            orjson_mock.dumps = orjson_dumps_with_datetime
            orjson_mock.OPT_NAIVE_UTC = 1
            orjson_mock.OPT_OMIT_MICROSECONDS = 2

            import importlib

            importlib.reload(typedefs)

            test_data = {
                "timestamp": datetime(2023, 1, 1, 12, 0, 0),
                "message": "datetime test",
            }

            payload = JsonPayload(test_data)
            data = payload._value
            parsed = json.loads(data.decode("utf-8"))

            assert parsed["_orjson_used"] is True
            assert parsed["data"]["message"] == "datetime test"
            assert parsed["data"]["timestamp"] == "2023-01-01T12:00:00"

    def test_encoding_with_orjson(self) -> None:
        """Test that JsonPayload respects encoding parameter with orjson."""
        with patch.dict(sys.modules, {"orjson": Mock()}):
            orjson_mock = sys.modules["orjson"]
            orjson_mock.dumps = mock_orjson_dumps
            orjson_mock.OPT_NAIVE_UTC = 1
            orjson_mock.OPT_OMIT_MICROSECONDS = 2

            import importlib

            importlib.reload(typedefs)

            test_data = {"unicode": "café", "emoji": "🚀"}

            # Test with default UTF-8 encoding
            payload_utf8 = JsonPayload(test_data)
            assert payload_utf8.encoding == "utf-8"

            # Test with custom encoding
            payload_latin1 = JsonPayload(test_data, encoding="latin-1")
            assert payload_latin1.encoding == "latin-1"


@pytest.fixture(autouse=True)
def reset_typedefs():
    """Reset typedefs module after each test."""
    yield
    # Reload typedefs to reset to original state
    import importlib

    importlib.reload(typedefs)
