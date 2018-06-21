#!/usr/bin/env python3

import aiohttp
import pathlib
from aiohttp import hdrs
from collections import defaultdict
import io
from pprint import pprint

headers = [getattr(hdrs, name)
           for name in dir(hdrs)
           if isinstance(getattr(hdrs, name), hdrs.istr)]

def factory():
    return defaultdict(factory)


TERMINAL = object()


def build(headers):
    dct = defaultdict(factory)
    for hdr in headers:
        d = dct
        for ch in hdr:
            d = d[ch]
        d[TERMINAL] = hdr
    return dct

dct = build(headers)


HEADER = """
#include "_find_header.h"

#define NEXT_CHAR() \\
{ \\
    count++; \\
    if (count == size) { \\
        /* end of search */ \\
        return -1; \\
    } \\
    pchar++; \\
    ch = *pchar; \\
    last = (count == size -1); \\
} while(0);

int
find_header(const char *str, int size)
{
    char *pchar = str;
    int last;
    char ch;
    int count = -1;
    pchar--;
"""

BLOCK = """
{label}:
    NEXT_CHAR();
    switch (ch) {{
{cases}
    default:
        return -1;
    }}
"""

CASE = """
    case '{char}':
        if (last) {{
            return {index};
        }}
        goto {next};
"""

FOOTER = """
missing:
    return -1;
}
"""

def gen_prefix(prefix, k):
    if k == '-':
        return prefix + '_'
    else:
        return prefix + k.upper()


def gen_block(dct, prefix, used_blocks, out):
    cases = []
    for k, v in dct.items():
        if k is TERMINAL:
            continue
        next_prefix = gen_prefix(prefix, k)
        term = v.get(TERMINAL)
        if term is not None:
            index = headers.index(term)
        else:
            index = -1
        case = CASE.format(char=k, index=index, next=next_prefix)
        cases.append(case)
        lo = k.lower()
        if lo != k:
            case = CASE.format(char=lo, index=index, next=next_prefix)
            cases.append(case)
    label = prefix if prefix else 'INITIAL'
    block = BLOCK.format(label=label, cases='\n'.join(cases))
    out.write(block)
    for k, v in dct.items():
        if not isinstance(v, defaultdict):
            continue
        block_name = gen_prefix(prefix, k)
        if block_name in used_blocks:
            continue
        used_blocks.add(block_name)
        gen_block(v, block_name, used_blocks, out)


def gen(dct):
    out = io.StringIO()
    out.write(HEADER)
    gen_block(dct, '', set(), out)
    out.write(FOOTER)
    return out


def gen_headers(headers):
    out = io.StringIO()
    out.write("from . import hdrs\n")
    out.write("cdef tuple headers = (\n")
    for hdr in headers:
        out.write("    hdrs.{},\n".format(hdr.upper().replace('-', '_')))
    out.write(")\n")
    return out

# print(gen(dct).getvalue())
# print(gen_headers(headers).getvalue())

folder = pathlib.Path(aiohttp.__file__).parent

with (folder / '_find_header.c').open('w') as f:
    f.write(gen(dct).getvalue())

with (folder / '_headers.pxi').open('w') as f:
    f.write(gen_headers(headers).getvalue())
