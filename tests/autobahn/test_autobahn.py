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
        except ConnectionRefusedError:
            time.sleep(0.01)
        else:
            return
        finally:
            sock.close()


def get_failed_tests(report_path: str, name: str) -> List[Dict[str, Any]]:
    report_path = Path(report_path)
    result_summary = json.loads((report_path / "index.json").read_text())[name]
    failed_messages = []
    PASS = {"OK", "INFORMATIONAL"}
    entry_fields = {"case", "description", "expectation", "expected", "received"}
    for results in result_summary.values():
        if results["behavior"] in PASS and results["behaviorClose"] in PASS:
            continue
        report = json.loads((report_path / results["reportfile"]).read_text())
        failed_messages.append({field: report[field] for field in entry_fields})
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

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
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

    assert not failed_messages, "\n".join(
        "\n\t".join(
            f"{field}: {msg[field]}"
            for field in ("case", "description", "expectation", "expected", "received")
        )
        for msg in failed_messages
    )
