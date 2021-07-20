import errno
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

HOST = "localhost"
PORT = 9001


@pytest.fixture(scope="module", autouse=True)
def create_report_directory(request: Any) -> None:
    path = Path(f"{request.fspath.dirname}/reports")
    if path.is_dir():
        shutil.rmtree(path)
    path.mkdir()


@pytest.fixture(scope="session", autouse=True)
def setup_venv() -> None:
    if not Path("tests/autobahn/autobahntestsuite-env").exists():
        print("Creating Python 2.7 environment and installing autobahntestsuite")
        subprocess.check_call(
            ["virtualenv", "-p", "python2.7", "tests/autobahn/autobahntestsuite-env"]
        )
        subprocess.check_call(
            [
                "tests/autobahn/autobahntestsuite-env/bin/pip",
                "install",
                "autobahntestsuite>=0.8.0",
            ]
        )


def wait_for_server(host: str, port: int) -> None:
    while True:
        sock = socket.socket()
        try:
            sock.connect((HOST, PORT))
        except OSError as sock_err:
            if sock_err.errno == errno.ECONNREFUSED:
                time.sleep(0.01)
            else:
                raise
        else:
            return
        finally:
            sock.close()


def get_failed_tests(report_path: str, name: str) -> List[Dict[str, Any]]:
    with open(Path(f"{report_path}/index.json")) as f:
        result_summary = json.load(f)[name]
    failed_messages = []
    PASS = {"OK", "INFORMATIONAL"}
    for results in result_summary.values():
        if results["behavior"] not in PASS or results["behaviorClose"] not in PASS:
            with open(Path(f"{report_path}/{results['reportfile']}")) as f:
                report = json.load(f)
                failed_messages.append(
                    {
                        "case": report["case"],
                        "description": report["description"],
                        "expectation": report["expectation"],
                        "expected": report["expected"],
                        "received": report["received"],
                    }
                )
    return failed_messages


def test_client() -> None:
    print("Starting autobahntestsuite server")
    server = subprocess.Popen(
        [
            "tests/autobahn/autobahntestsuite-env/bin/wstest",
            "-m",
            "fuzzingserver",
            "-s",
            "tests/autobahn/client/fuzzingserver.json",
        ]
    )
    print("Waiting for server to start")
    wait_for_server(HOST, PORT)
    try:
        print("Running wsproto test client")
        client = subprocess.Popen(
            [sys.executable] + ["tests/autobahn/client/client.py"]
        )
        client.wait()
    finally:
        print("Stopping server")
        client.terminate()
        client.wait()
        server.terminate()
        server.wait()

    failed_messages = get_failed_tests("tests/autobahn/reports/clients", "aiohttp")

    if failed_messages:
        pytest.xfail(
            "\n".join(
                [
                    f"case: {msg['case']}"
                    f"\ndescription: {msg['description']}"
                    f"\nexpectation: {msg['expectation']}"
                    f"\nexpected: {msg['expected']}"
                    f"\nreceived: {msg['received']}"
                    for msg in failed_messages
                ]
            )
        )


def test_server() -> None:
    print("Starting wsproto test server")
    server = subprocess.Popen([sys.executable] + ["tests/autobahn/server/server.py"])
    try:
        print("Waiting for server to start")
        wait_for_server(HOST, PORT)
        print("Starting autobahntestsuite client")
        client = subprocess.Popen(
            [
                "tests/autobahn/autobahntestsuite-env/bin/wstest",
                "-m",
                "fuzzingclient",
                "-s",
                "tests/autobahn/server/fuzzingclient.json",
                "-o",
                "tests/autobahn/reports/servers",
            ]
        )
        client.wait()
    finally:
        print("Stopping server")
        client.terminate()
        client.wait()
        server.terminate()
        server.wait()

    failed_messages = get_failed_tests(
        "tests/autobahn/reports/servers", "AutobahnServer"
    )

    if failed_messages:
        pytest.xfail(
            "\n".join(
                [
                    f"case: {msg['case']}"
                    f"\ndescription: {msg['description']}"
                    f"\nexpectation: {msg['expectation']}"
                    f"\nexpected: {msg['expected']}"
                    f"\nreceived: {msg['received']}"
                    for msg in failed_messages
                ]
            )
        )
