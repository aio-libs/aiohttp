#!/usr/bin/python3

# Copyright 2022-2025 Google LLC, 2026 aio-libs contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import sys
from contextlib import suppress
from unittest import mock

import atheris  # noqa: I900

with atheris.instrument_imports():
    from aiohttp import StreamReader
    from aiohttp.base_protocol import BaseProtocol
    from aiohttp.http_exceptions import BadHttpMessage
    from aiohttp.http_parser import HeadersParser, HttpPayloadParser

LOOP = mock.create_autospec(asyncio.AbstractEventLoop, spec_set=True, instance=True)
PROTOCOL = BaseProtocol(LOOP)


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    out = StreamReader(PROTOCOL, 2**16, loop=LOOP)
    parser = HttpPayloadParser(out, headers_parser=HeadersParser())
    with suppress(BadHttpMessage):
        parser.feed_data(data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
