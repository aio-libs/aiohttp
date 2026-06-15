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
import io
import sys

import atheris

with atheris.instrument_imports():
    from aiohttp import BodyPartReader
    from aiohttp.hdrs import CONTENT_TYPE


class FuzzStream:
    def __init__(self, content: bytes):
        self.content = io.BytesIO(content)

    async def read(self, size: int | None = None) -> bytes:
        return self.content.read(size)

    def at_eof(self) -> bool:
        return self.content.tell() == len(self.content.getbuffer())

    async def readline(self) -> bytes:
        return self.content.readline()

    def unread_data(self, data: bytes) -> None:
        self.content = io.BytesIO(data + self.content.read())


@atheris.instrument_func
async def fuzz_bodypart_reader(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    obj = BodyPartReader(
        b"--:",
        {CONTENT_TYPE: fdp.ConsumeUnicode(30)},
        FuzzStream(fdp.ConsumeBytes(atheris.ALL_REMAINING)),
    )
    if not obj.at_eof():
        await obj.form()


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    with suppress(ValueError):
        asyncio.run(fuzz_bodypart_reader(data))


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
