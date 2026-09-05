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

import sys
from contextlib import suppress

import atheris  # noqa: I900

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from yarl import URL

    from aiohttp.payload import StringPayload


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]
    original = fdp.ConsumeString(sys.maxsize)

    with suppress(UnicodeEncodeError):
        StringPayload(original)
    with suppress(ValueError):
        URL(original)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)  # type: ignore[attr-defined]
    atheris.Fuzz()  # type: ignore[attr-defined]
