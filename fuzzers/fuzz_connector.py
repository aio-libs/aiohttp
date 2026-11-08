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
import hashlib
import logging
import random
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from unittest import mock

import atheris  # noqa: I900
import yarl

# with atheris.instrument_imports():  # type: ignore[attr-defined]
import aiohttp
from aiohttp.client_exceptions import ClientConnectorError
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ConnectionKey
from aiohttp.http2.connection import Http2Protocol

from utils import MockTransport


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("fuzz.connector")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    logger.addHandler(_handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


# ---------------------------------------------------------------------------
# Action space
# ---------------------------------------------------------------------------
ACTION_CONNECT = 0
ACTION_RELEASE = 1
ACTION_ERROR = 2
ACTION_STUTTER = 3
ACTION_NAMES = {
    ACTION_CONNECT: "connect",
    ACTION_RELEASE: "release",
    ACTION_ERROR: "error",
    ACTION_STUTTER: "stutter",
}

N_MAX_STEPS = 20
MAX_HOSTS = 3


# ---------------------------------------------------------------------------
# Permutation identity
# ---------------------------------------------------------------------------
@dataclass
class Permutation:
    seed: int
    n_steps: int
    n_hosts: int
    seq: int = 0

    @property
    def id(self) -> str:
        return f"{self.seed:08x}-{self.seq:05d}"

    def describe(self) -> str:
        return f"id={self.id} n_steps={self.n_steps} n_hosts={self.n_hosts}"


def _permutation_id(data: bytes) -> int:
    return int.from_bytes(hashlib.blake2s(data, digest_size=4).digest(), "big")


_seq_counter = 0


def _next_seq() -> int:
    global _seq_counter
    _seq_counter += 1
    return _seq_counter


# ---------------------------------------------------------------------------
# Live connection handle
# ---------------------------------------------------------------------------
@dataclass
class LiveConn:
    cid: int
    host_id: int
    connection: object  # aiohttp.Connection
    request: "MockRequest"


class MockRequest:
    def __init__(self, host_id: int) -> None:
        host = f"127.0.0.{host_id + 1}"
        self.connection_key = ConnectionKey(
            host=host,
            port=80,
            is_ssl=False,
            ssl=None,
            proxy=None,
            proxy_headers_hash=None,
            server_hostname=None,
        )
        self.proxy = None
        self.ssl = None
        self.url = yarl.URL(f"http://{host}/")

    def is_ssl(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Pool invariants
# ---------------------------------------------------------------------------
def _snapshot(conn) -> dict:
    return {
        "conns": {str(k): len(v) for k, v in conn._conns.items()},
        "multiplexed": {str(k): len(v) for k, v in conn._multiplexed.items()},
        "acquired": len(conn._acquired),
        "acquired_per_host": {
            str(k): len(v) for k, v in conn._acquired_per_host.items()
        },
        "waiters": {str(k): len(v) for k, v in conn._waiters.items()},
        "cleanup_closed_transports": len(conn._cleanup_closed_transports),
    }


def assert_pool_consistent(conn, where: str = "") -> None:
    snap = _snapshot(conn)

    # 1. No key in both pools.
    assert not conn._conns, "HTTP/2 connection found in the _conns pool"

    # 2. acquired_per_host subset of acquired.
    for key, protos in conn._acquired_per_host.items():
        leaked = protos - conn._acquired
        if leaked:
            logger.error(
                "pool invariant VIOLATED at %s: leaked acquired_per_host[%s]=%s",
                where, key, leaked,
            )
            logger.error("pool snapshot: %s", snap)
        assert not leaked, f"acquired_per_host[{key}] not in acquired: {leaked}"

    # 3. Total acquired never exceeds limit.
    if conn._limit and len(conn._acquired) > conn._limit:
        logger.error("pool invariant VIOLATED at %s: acquired over limit %d > %d",
                     where, len(conn._acquired), conn._limit)
        logger.error("pool snapshot: %s", snap)
    assert not conn._limit or len(conn._acquired) <= conn._limit

    # 4. Per-host pool never exceeds limit_per_host.
    if conn._limit_per_host:
        for key in set(conn._conns) | set(conn._multiplexed):
            n = len(conn._conns.get(key, ())) + len(conn._multiplexed.get(key, ()))
            if n > conn._limit_per_host:
                logger.error(
                    "pool invariant VIOLATED at %s: per-host overflow %s=%d",
                    where, key, n,
                )
                logger.error("pool snapshot: %s", snap)
            assert n <= conn._limit_per_host

    logger.debug("pool ok at %s: %s", where, snap)


def assert_pool_clean(conn, where: str = "") -> None:
    snap = _snapshot(conn)
    problems = []
    if dict(conn._conns) != {}:
        problems.append(f"_conns={dict(conn._conns)}")
    if dict(conn._multiplexed) != {}:
        problems.append(f"_multiplexed={dict(conn._multiplexed)}")
    if conn._acquired != set():
        problems.append(f"_acquired={conn._acquired}")
    if dict(conn._acquired_per_host) != {}:
        problems.append(f"_acquired_per_host={dict(conn._acquired_per_host)}")
    if dict(conn._waiters) != {}:
        problems.append(f"_waiters={dict(conn._waiters)}")
    if conn._cleanup_closed_transports != []:
        problems.append(f"_cleanup_closed={conn._cleanup_closed_transports}")

    if problems:
        logger.error("pool not clean at %s: %s", where, "; ".join(problems))
        logger.error("pool snapshot: %s", snap)

    assert dict(conn._conns) == {}
    assert dict(conn._multiplexed) == {}
    assert conn._acquired == set()
    assert dict(conn._acquired_per_host) == {}
    assert dict(conn._waiters) == {}
    assert conn._cleanup_closed_transports == []
    logger.debug("pool clean at %s", where)


# ---------------------------------------------------------------------------
# Step loop
# ---------------------------------------------------------------------------
@atheris.instrument_func  # type: ignore[attr-defined]
async def fuzz_connector(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]

    n_steps = fdp.ConsumeIntInRange(1, N_MAX_STEPS)
    n_hosts = fdp.ConsumeIntInRange(1, MAX_HOSTS)
    host_ids = list(range(n_hosts))
    http2_enabled = 1
    # disabled; we aren't testing these
    limit = MAX_HOSTS
    limit_per_host = 1

    perm = Permutation(
        seed=_permutation_id(data),
        n_steps=n_steps,
        n_hosts=n_hosts,
        seq=_next_seq(),
    )
    logger.info(
        "=== start %s http2=%s limit=%d limit_per_host=%d",
        perm.describe(), http2_enabled, limit, limit_per_host,
    )

    conn = aiohttp.TCPConnector(
        limit=limit,
        limit_per_host=limit_per_host,
        http2_enabled=http2_enabled,
    )
    loop = asyncio.get_running_loop()

    live: dict[int, LiveConn] = {}
    pending: dict[int, tuple[int, MockRequest, asyncio.Task]] = {}
    state = {"next_cid": 0, "create_attempt": 0}

    async def maybe_connect(*args, **kwargs):
        i = state["create_attempt"]
        state["create_attempt"] += 1
        assert_pool_consistent(conn, f"{perm.id} enter-create#{i}")

        req = kwargs.get("req")
        key = req.connection_key if req is not None else MockRequest(0).connection_key

        if fdp.ConsumeIntInRange(0, 9) == 0:
            logger.info("[%s] create#%d host=%s -> INJECTED FAILURE",
                        perm.id, i, key.host)
            raise ClientConnectorError(key, OSError("fuzz-injected"))

        if http2_enabled:
            proto = Http2Protocol(loop)
        else:
            proto = ResponseHandler(loop)
        transport = MockTransport()
        proto.connection_made(transport)

        logger.info("[%s] create#%d host=%s -> %s",
                    perm.id, i, key.host, type(proto).__name__)
        assert_pool_consistent(conn, f"{perm.id} exit-create#{i}")
        return transport, proto

    def spawn_connect() -> None:
        cid = state["next_cid"]
        state["next_cid"] += 1
        host_id = random.choice(host_ids)
        req = MockRequest(host_id)
        task = asyncio.create_task(
            conn.connect(req, [], aiohttp.ClientTimeout(total=1))
        )
        pending[cid] = (host_id, req, task)
        logger.info("[%s] step: connect cid=%d host=%d",
                    perm.id, cid, host_id)

    def do_release() -> None:
        cid = random.choice(list(live.keys()))
        entry = live.pop(cid)
        try:
            entry.connection.release()
        except BaseException as e:
            logger.error("[%s] release cid=%d raised: %r", perm.id, cid, e)
            raise
        logger.info("[%s] step: release cid=%d host=%d",
                    perm.id, cid, entry.host_id)

    def do_error() -> None:
        cid = random.choice(list(live.keys()))
        entry = live.pop(cid)
        try:
            proto = entry.connection.protocol
            if proto is not None:
                proto.connection_lost(OSError("fuzz-injected-error"))
            entry.connection.release()
        except BaseException as e:
            logger.error("[%s] error cid=%d raised: %r", perm.id, cid, e)
            raise
        logger.info("[%s] step: error cid=%d host=%d",
                    perm.id, cid, entry.host_id)

    async def drain() -> None:
        # Give the loop a bounded number of turns so pending connects can
        # make progress without starving the step driver.
        for _ in range(4):
            await asyncio.sleep(0)

        done_ids = [cid for cid, (_, _, t) in pending.items() if t.done()]
        for cid in done_ids:
            host_id, req, task = pending.pop(cid)
            try:
                connection = task.result()
            except BaseException as e:
                logger.debug("[%s] pending cid=%d failed: %r", perm.id, cid, e)
                continue
            live[cid] = LiveConn(cid, host_id, connection, req)
            logger.debug("[%s] connect cid=%d host=%d completed",
                         perm.id, cid, host_id)

    with mock.patch.object(
        conn,
        "_wrap_create_connection",
        autospec=True,
        spec_set=True,
        side_effect=maybe_connect,
    ):
        for step in range(n_steps):
            action = fdp.ConsumeIntInRange(0, 3)

            # Fall back to connect when the chosen action has no target.
            if action in (ACTION_RELEASE, ACTION_ERROR) and not live:
                action = ACTION_CONNECT

            if action == ACTION_CONNECT:
                spawn_connect()
            # consider closing the connection as well
            elif action == ACTION_RELEASE:
                do_release()
            elif action == ACTION_ERROR:
                do_error()
            else:
                logger.info("[%s] step: stutter", perm.id)

            await drain()
            assert_pool_consistent(conn, f"{perm.id} step-{step}")

        # -------- final drain --------
        if pending:
            tasks = [t for (_, _, t) in pending.values()]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                logger.error("[%s] final drain timed out: %s",
                             perm.id, _snapshot(conn))
                raise AssertionError("final drain timed out") from None
            for cid, (host_id, req, task) in list(pending.items()):
                if task.done() and not task.cancelled():
                    try:
                        connection = task.result()
                        live[cid] = LiveConn(cid, host_id, connection, req)
                    except BaseException:
                        pass
            pending.clear()

        # -------- release everything --------
        for cid in list(live.keys()):
            entry = live.pop(cid)
            entry.connection._protocol.connection_lost(Exception)
            entry.connection.release()

        assert_pool_consistent(conn, f"{perm.id} pre-close")

    await asyncio.wait_for(conn.close(), timeout=1.0)
    assert_pool_clean(conn, f"{perm.id} post-close")
    logger.info("=== end %s", perm.describe())


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:
    asyncio.run(fuzz_connector(data))


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
