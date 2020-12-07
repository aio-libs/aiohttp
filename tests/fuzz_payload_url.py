#!/usr/bin/python3
import sys
import atheris

# aiohttp specific
from aiohttp import http_exceptions, payload

from yarl import URL

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeString(sys.maxsize)

    try:
        p = payload.StringPayload(original)
    except UnicodeEncodeError:
        None

    try:
        u = URL(original)
    except ValueError:
        None

    return

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
