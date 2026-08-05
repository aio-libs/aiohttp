#!/usr/bin/python3
import sys

import atheris
from yarl import URL

from aiohttp import payload


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeString(sys.maxsize)

    try:
        payload.StringPayload(original)
    except UnicodeEncodeError:
        None

    try:
        URL(original)
    except ValueError:
        None

    return


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
