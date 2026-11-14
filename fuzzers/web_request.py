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

import atheris  # noqa: I900

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from multidict import CIMultiDict
    from yarl import URL

    from aiohttp.test_utils import make_mocked_request


@atheris.instrument_func  # type: ignore[attr-defined]
async def fuzz_run_one_async(data: bytes) -> None:  # type: ignore[misc]
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]
    url_s = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 512))
    try:
        URL(url_s)
    except ValueError:
        return

    # Decode like the parsers do, so that non-UTF-8 header bytes are covered.
    name = fdp.ConsumeBytes(20).decode("utf-8", "surrogateescape")
    value_len = fdp.ConsumeIntInRange(0, 512)
    value = fdp.ConsumeBytes(value_len).decode("utf-8", "surrogateescape")
    headers = CIMultiDict({name: value})
    req = make_mocked_request("GET", url_s, headers=headers)

    req.forwarded
    await req.post()


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:  # type: ignore[misc]
    asyncio.run(fuzz_run_one_async(data))


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)  # type: ignore[attr-defined]
    atheris.Fuzz()  # type: ignore[attr-defined]
