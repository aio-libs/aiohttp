from aiohttp import web


def test_reexported_classes_report_public_module() -> None:
    assert web.Response.__module__ == "aiohttp.web"
    assert web.WebSocketResponse.__module__ == "aiohttp.web"
