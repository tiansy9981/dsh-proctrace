import json
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ)
ENV["PYTHONPATH"] = os.path.join(ROOT, "src") + (
    ":" + ENV["PYTHONPATH"] if ENV.get("PYTHONPATH") else ""
)


def run_cli(*args, timeout=15):
    return subprocess.run(
        [sys.executable, "-m", "proctrace"] + list(args),
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_doctor():
    result = run_cli("doctor")
    assert result.returncode == 0, result.stderr
    assert "proctrace doctor" in result.stdout
    assert "backend:" in result.stdout


def test_init_and_validate(tmp_path):
    path = tmp_path / "proctrace.json"
    result = run_cli("init", "--path", str(path))
    assert result.returncode == 0, result.stderr
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "protected" in data
    # init refuses to overwrite without --force
    again = run_cli("init", "--path", str(path))
    assert again.returncode == 2


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="macOS/Linux only")
def test_snapshot_json(tmp_path):
    target = tmp_path / "cli-hold.txt"
    script = (
        "import sys, time\n"
        "f = open(sys.argv[1], 'w'); f.write('x'); f.flush()\n"
        "print('ready', flush=True)\n"
        "time.sleep(20)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        result = run_cli("snapshot", "--pid", str(proc.pid), "--json")
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["target_pid"] == proc.pid
        paths = [
            f["path"]
            for process in data["processes"]
            for f in process["files"]
        ]
        assert any(p.endswith("cli-hold.txt") for p in paths), paths
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="macOS/Linux only")
def test_watch_json_captures_late_open(tmp_path):
    target = tmp_path / "late-open.txt"
    script = (
        "import sys, time\n"
        "time.sleep(0.8)\n"
        "f = open(sys.argv[1], 'w'); f.write('x'); f.flush()\n"
        "time.sleep(4)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(target)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        result = run_cli(
            "watch",
            "--pid",
            str(proc.pid),
            "--duration",
            "2.2",
            "--interval",
            "0.2",
            "--no-tui",
            "--json",
            "--quiet",
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        paths = [e.get("path", "") for e in events if e["kind"] == "open"]
        assert any(p.endswith("late-open.txt") for p in paths), events
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="macOS/Linux only")
def test_snapshot_audit_violation(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside-secret.txt"
    script = (
        "import sys, time\n"
        "f = open(sys.argv[1], 'w'); f.write('x'); f.flush()\n"
        "print('ready', flush=True)\n"
        "time.sleep(20)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(outside)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        result = run_cli(
            "snapshot",
            "--pid",
            str(proc.pid),
            "--json",
            "--audit",
            "--workspace",
            str(ws),
            "--no-default-audit-paths",
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        violations = data.get("violations") or []
        assert any(v["path"].endswith("outside-secret.txt") for v in violations), data
        assert any(v["reason"] == "outside_workspace" for v in violations), violations
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="macOS/Linux only")
def test_snapshot_network_connections(tmp_path):
    script = (
        "import socket, time\n"
        "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\n"
        "port = s.getsockname()[1]\n"
        "c = socket.create_connection(('127.0.0.1', port))\n"
        "print('ready', flush=True)\n"
        "time.sleep(20)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        result = run_cli("snapshot", "--pid", str(proc.pid), "--network", "--json")
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        connections = data.get("connections") or []
        assert connections
        assert all(c["pid"] == proc.pid for c in connections)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="SQLite shim platform")
def test_run_sqlite_audit_json(tmp_path):
    from proctrace.db_audit import find_sqlite_shim

    if not find_sqlite_shim():
        pytest.skip("SQLite shim not built")
    sock = "/tmp/proctrace-cli-test-%d.sock" % os.getpid()
    dbpath = tmp_path / "cli.db"
    code = (
        "import sqlite3, time\n"
        "c=sqlite3.connect(%r)\n"
        "c.execute('create table t(x)')\n"
        "c.execute('insert into t values (1)')\n"
        "c.execute('select * from t').fetchall()\n"
        "time.sleep(0.2)\n"
        "c.close()\n"
    ) % str(dbpath)
    result = run_cli(
        "run",
        "--db-audit",
        "sqlite:" + sock,
        "--no-tui",
        "--duration",
        "2",
        "--json",
        "--quiet",
        "--",
        sys.executable,
        "-c",
        code,
        timeout=15,
    )
    try:
        assert result.returncode == 0, result.stderr
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        queries = [e for e in events if e["kind"] == "db_query"]
        assert queries, events
        assert any("create table" in q["db"]["sql"].lower() for q in queries)
        assert all(q["db"].get("agent_pid") for q in queries)
    finally:
        try:
            os.unlink(sock)
        except OSError:
            pass
