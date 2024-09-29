import asyncio
import atexit
import math
import os
import signal
from typing import List, Tuple

PORT = 8888

server = os.fork()
if server == 0:
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(lambda *_: None, port=PORT)
    loop.run_until_complete(coro)
    loop.run_forever()
else:
    atexit.register(os.kill, server, signal.SIGTERM)


async def write_joined_bytearray(writer, chunks):
    body = bytearray(chunks[0])
    for c in chunks[1:]:
        body += c
    writer.write(body)


async def write_joined_list(writer, chunks):
    body = b"".join(chunks)
    writer.write(body)


async def write_separately(writer, chunks):
    for c in chunks:
        writer.write(c)


def fm_size(s, _fms=("", "K", "M", "G")):
    i = 0
    while s >= 1024:
        s /= 1024
        i += 1
    return f"{s:.0f}{_fms[i]}B"


def fm_time(s, _fms=("", "m", "µ", "n")):
    if s == 0:
        return "0"
    i = 0
    while s < 1:
        s *= 1000
        i += 1
    return f"{s:.2f}{_fms[i]}s"


def _job(j: List[int]) -> Tuple[str, List[bytes]]:
    # Always start with a 256B headers chunk
    body = [b"0" * s for s in [256] + list(j)]
    job_title = f"{fm_size(sum(j))} / {len(j)}"
    return (job_title, body)


writes = [
    ("b''.join", write_joined_list),
    ("bytearray", write_joined_bytearray),
    ("multiple writes", write_separately),
]

bodies = (
    [],
    [10 * 2**0],
    [10 * 2**7],
    [10 * 2**17],
    [10 * 2**27],
    [50 * 2**27],
    [1 * 2**0 for _ in range(10)],
    [1 * 2**7 for _ in range(10)],
    [1 * 2**17 for _ in range(10)],
    [1 * 2**27 for _ in range(10)],
    [10 * 2**27 for _ in range(5)],
)


jobs = [_job(j) for j in bodies]


async def time(loop, fn, *args):
    spent = []
    while not spent or sum(spent) < 0.2:
        s = loop.time()
        await fn(*args)
        e = loop.time()
        spent.append(e - s)
    mean = sum(spent) / len(spent)
    sd = sum((x - mean) ** 2 for x in spent) / len(spent)
    return len(spent), mean, math.sqrt(sd)


async def main(loop):
    _, writer = await asyncio.open_connection(port=PORT)
    print("Loop:", loop)
    print("Transport:", writer._transport)
    res = [
        ("size/chunks", "Write option", "Mean", "Std dev", "loops", "Variation"),
    ]
    res.append([":---", ":---", "---:", "---:", "---:", "---:"])

    async def bench(job_title, w, body, base=None):
        it, mean, sd = await time(loop, w[1], writer, c)
        res.append(
            (
                job_title,
                w[0],
                fm_time(mean),
                fm_time(sd),
                str(it),
                f"{mean / base - 1:.2%}" if base is not None else "",
            )
        )
        return mean

    for t, c in jobs:
        print("Doing", t)
        base = await bench(t, writes[0], c)
        for w in writes[1:]:
            await bench("", w, c, base)
    return res


loop = asyncio.get_event_loop()
results = loop.run_until_complete(main(loop))
with open("bench.md", "w") as f:
    for line in results:
        f.write("| {} |\n".format(" | ".join(line)))
