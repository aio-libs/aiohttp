class MockTransport:
    """Minimal asyncio.Transport replacement.
    """

    def __init__(self) -> None:
        self._closing = False
        self._protocol = None
        self._extra = {"sslcontext": None, "peername": ("127.0.0.1", 0)}
        self._written = bytearray()

    def set_protocol(self, proto) -> None:
        self._protocol = proto

    def get_protocol(self):
        return self._protocol

    def is_closing(self) -> bool:
        return self._closing

    def close(self) -> None:
        self._closing = True

    def abort(self) -> None:
        self._closing = True

    def is_reading(self) -> bool:
        return not self._closing

    def get_extra_info(self, name, default=None):
        return self._extra.get(name, default)

    def write(self, data) -> None:
        self._written.extend(data)

    def writelines(self, data) -> None:
        for chunk in data:
            self._written.extend(chunk)

    def pause_reading(self) -> None:
        pass

    def resume_reading(self) -> None:
        pass
