#!/usr/bin/python3

# Copyright 2026 aio-libs contributors
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

import logging
import sys

import atheris  # noqa: I900

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from yarl import URL

    from aiohttp._cookie_helpers import parse_set_cookie_headers
    from aiohttp.cookiejar import CookieJar

logging.disable(logging.CRITICAL)
URL_ = URL("https://example.com/")


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:  # type: ignore[misc]
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]
    jar = CookieJar(quote_cookie=fdp.ConsumeBool())
    headers = [
        fdp.ConsumeUnicode(fdp.ConsumeIntInRange(0, 256))
        for _ in range(fdp.ConsumeIntInRange(1, 4))
    ]
    # The jar skips its storage check for these, relying on the parser.
    for _, morsel in parse_set_cookie_headers(headers):
        assert jar._can_send(morsel), (headers, morsel)
    jar.update_cookies_from_headers(headers, URL_)
    jar.filter_cookies(URL_).output(header="Cookie:", sep=";").encode()


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)  # type: ignore[attr-defined]
    atheris.Fuzz()  # type: ignore[attr-defined]
