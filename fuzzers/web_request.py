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
import os
import sys

import atheris

with atheris.instrument_imports():
    import aiohttp
    from aiohttp.test_utils import make_mocked_request
    from multidict import CIMultiDict
    from yarl import URL

@atheris.instrument_func
async def fuzz_run_one_async(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    url_s = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 512))
    try:
        URL(url_s)
    except ValueError:
        return

    headers = CIMultiDict(
        {fdp.ConsumeString(20): fdp.ConsumeString(fdp.ConsumeIntInRange(0, 512))}
    )
    req = make_mocked_request("GET", url_s, headers=headers)

    req.forwarded
    ret = await req.post()

@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    asyncio.run(fuzz_run_one_async(data))

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
