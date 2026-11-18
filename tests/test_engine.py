import os
import sys
import time
import subprocess

import pytest

from proctrace.collector import Collector, make_collector
from proctrace.config import Config
from proctrace.engine import Monitor
from proctrace.model import FdInfo
from proctrace.policy import Policy, Rule


class FakeCollector(Collector):
    name = "fake"

    def __init__(self):
        self.by_pid = {}

    def list_fds(self, pid):
        return dict(self.by_pid.get(pid, {}))


def test_fd_diff_open_change_close():
    collector = FakeCollector()
    pid = os.getpid()
    collector.by_pid[pid] = {3: FdInfo(fd=3, path="/tmp/a.txt", kind="file")}
    monitor = Monitor(
        pid,
        collector,
        Config(interval=0.1),
        follow_children=False,
        show_initial=False,
    )

    first = monitor.poll()
    assert not [e for e in first if e.kind == "open"]
    assert monitor.files_for(pid)[0].path == "/tmp/a.txt"

    collector.by_pid[pid][4] = FdInfo(fd=4, path="/tmp/b.txt", kind="file")
    second = monitor.poll()
    opens = [e for e in second if e.kind == "open"]
    assert [(e.fd, e.path) for e in opens] == [(4, "/tmp/b.txt")]

    collector.by_pid[pid][3] = FdInfo(fd=3, path="/tmp/c.txt", kind="file")
    third = monitor.poll()
    changes = [e for e in third if e.kind == "change"]
    assert changes and changes[0].fd == 3
    assert "a.txt" in changes[0].detail and "c.txt" in changes[0].detail

    del collector.by_pid[pid][4]
    fourth = monitor.poll()
    closes = [e for e in fourth if e.kind == "close"]
    assert [(e.fd, e.path) for e in closes] == [(4, "/tmp/b.txt")]
    assert [f.fd for f in monitor.files_for(pid)] == [3]


def test_initial_events_are_optional():
    collector = FakeCollector()
    pid = os.getpid()
    collector.by_pid[pid] = {9: FdInfo(fd=9, path="/tmp/initial.txt", kind="file")}
    monitor = Monitor(
        pid,
        collector,
        Config(interval=0.1),
        follow_children=False,
        show_initial=True,
    )
    events = monitor.poll()
    opens = [e for e in events if e.kind == "open"]
    assert len(opens) == 1
    assert opens[0].initial is True


def _spawn_holder(path):
    script = (
        "import sys, time\n"
        "f = open(sys.argv[1], 'w')\n"
        "f.write('x'); f.flush()\n"
        "print('ready', flush=True)\n"
        "time.sleep(30)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout.readline().strip() == "ready"
    return proc


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="macOS/Linux only")
def test_real_process_open_file(tmp_path):
    target = tmp_path / "real-hold.txt"
    proc = _spawn_holder(target)
    try:
        monitor = Monitor(
            proc.pid,
            make_collector("auto"),
            Config(interval=0.1),
            follow_children=False,
            show_initial=True,
        )
        found = []
        deadline = time.time() + 3
        while time.time() < deadline:
            monitor.poll()
            found = [f.path for f in monitor.files_for(proc.pid) if f.path.endswith(target.name)]
            if found:
                break
            time.sleep(0.1)
        assert found, "expected to observe %s" % target
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux procfs only")
def test_protected_procfs_alert():
    victim = os.getpid()
    script = (
        "import sys, time\n"
        "f = open('/proc/%d/cmdline', 'rb')\n"
        "f.read()\n"
        "print('ready', flush=True)\n"
        "time.sleep(20)\n" % victim
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout.readline().strip() == "ready"
    try:
        policy = Policy([Rule(pid=victim)], [])
        monitor = Monitor(
            proc.pid,
            make_collector("auto"),
            Config(interval=0.1),
            policy=policy,
            follow_children=False,
        )
        monitor.preflight()
        events = monitor.poll()
        alerts = [e for e in events if e.kind == "alert"]
        assert alerts, "expected a protected-process alert"
        assert alerts[0].victim_pid == victim
        assert alerts[0].via == "procfs"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_protected_path_alert_with_fake_collector():
    collector = FakeCollector()
    pid = os.getpid()
    collector.by_pid[pid] = {
        3: FdInfo(fd=3, path="/proc/999/mem", kind="file")
    }
    policy = Policy([Rule(pid=999)], [])
    monitor = Monitor(
        pid,
        collector,
        Config(interval=0.1),
        policy=policy,
        follow_children=False,
    )
    monitor.preflight()
    events = monitor.poll()
    alerts = [e for e in events if e.kind == "alert"]
    assert alerts
    assert alerts[0].victim_pid == 999
    assert alerts[0].via == "procfs"


def test_ptrace_alert_with_fake_collector():
    class PtraceCollector(FakeCollector):
        def ptrace_tracer(self, pid):
            return os.getpid()

    collector = PtraceCollector()
    pid = os.getpid()
    policy = Policy([Rule(pid=999)], [])
    monitor = Monitor(
        pid,
        collector,
        Config(interval=0.1),
        policy=policy,
        follow_children=False,
    )
    monitor.preflight()
    events = monitor.poll()
    alerts = [e for e in events if e.kind == "alert" and e.via == "ptrace"]
    assert alerts
    assert alerts[0].victim_pid == 999


def test_tree_discovery_is_cached_between_polls():
    collector = FakeCollector()
    pid = os.getpid()
    monitor = Monitor(
        pid,
        collector,
        Config(interval=0.1, tree_refresh=10.0),
        follow_children=False,
    )
    calls = []
    original = monitor._build_tree

    def counting(events):
        calls.append(1)
        return original(events)

    monitor._build_tree = counting
    monitor.poll()
    monitor.poll()
    assert len(calls) == 1


def test_path_audit_violation_and_no_duplicate(tmp_path):
    from proctrace.config import AuditConfig
    from proctrace.pathpolicy import PathAudit

    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    audit = PathAudit(
        AuditConfig(
            enabled=True,
            workspaces=[str(ws)],
            use_defaults=False,
            outside_workspace=True,
        ),
        platform=sys.platform,
    )
    collector = FakeCollector()
    pid = os.getpid()
    collector.by_pid[pid] = {3: FdInfo(fd=3, path=str(outside), kind="file")}
    monitor = Monitor(
        pid,
        collector,
        Config(interval=0.1),
        follow_children=False,
        path_audit=audit,
    )
    first = monitor.poll()
    violations = [e for e in first if e.kind == "violation"]
    assert len(violations) == 1
    assert violations[0].reason == "outside_workspace"
    assert violations[0].path == str(outside)
    assert "path-audit" in monitor.capabilities()

    second = monitor.poll()
    assert not [e for e in second if e.kind == "violation"]


def test_path_audit_ignores_stdio_by_default(tmp_path):
    from proctrace.config import AuditConfig
    from proctrace.pathpolicy import PathAudit

    ws = tmp_path / "ws"; ws.mkdir()
    outside = tmp_path / "log.txt"
    collector = FakeCollector()
    pid = os.getpid()
    collector.by_pid[pid] = {1: FdInfo(fd=1, path=str(outside), kind="file")}
    audit = PathAudit(
        AuditConfig(enabled=True, workspaces=[str(ws)], use_defaults=False),
        platform=sys.platform,
    )
    monitor = Monitor(pid, collector, Config(interval=0.1), follow_children=False, path_audit=audit)
    assert not [e for e in monitor.poll() if e.kind == "violation"]

    audit2 = PathAudit(
        AuditConfig(
            enabled=True,
            workspaces=[str(ws)],
            use_defaults=False,
            include_stdio=True,
        ),
        platform=sys.platform,
    )
    monitor2 = Monitor(os.getpid(), FakeCollector(), Config(interval=0.1),
                       follow_children=False, path_audit=audit2)
    monitor2.collector.by_pid[pid] = {1: FdInfo(fd=1, path=str(outside), kind="file")}
    assert [e for e in monitor2.poll() if e.kind == "violation"]


class FakeKernel:
    name = "fake-kernel"

    def __init__(self):
        self.events = []

    def start(self):
        pass

    def update_pids(self, pids):
        self.pids = set(pids)

    def drain(self):
        events = self.events
        self.events = []
        return events

    def close(self):
        pass

    @property
    def last_error(self):
        return ""

    @property
    def healthy(self):
        return True


def test_kernel_events_feed_path_audit_and_database(tmp_path):
    from proctrace.config import AuditConfig, DatabaseConfig
    from proctrace.kernel import KernelFileEvent
    from proctrace.pathpolicy import PathAudit

    ws = tmp_path / "ws"; ws.mkdir()
    audit = PathAudit(
        AuditConfig(enabled=True, workspaces=[str(ws)], use_defaults=False),
        platform=sys.platform,
    )
    kernel = FakeKernel()
    collector = FakeCollector()
    pid = os.getpid()
    collector.by_pid[pid] = {}
    cfg = Config(interval=0.1)
    cfg.database = DatabaseConfig(enabled=True)
    monitor = Monitor(
        pid,
        collector,
        cfg,
        follow_children=False,
        path_audit=audit,
        kernel_source=kernel,
    )
    monitor.poll()
    outside = str(tmp_path / "secret.txt")
    db_path = str(ws / "app.sqlite")
    kernel.events = [
        KernelFileEvent(ts=1.0, pid=pid, kind="open", path=outside, mode="r"),
        KernelFileEvent(ts=1.1, pid=pid, kind="open", path=db_path, mode="rw"),
    ]
    events = monitor.poll()
    opens = [e for e in events if e.kind == "open" and e.via == "kernel"]
    assert len(opens) == 2
    violations = [e for e in events if e.kind == "violation"]
    assert violations and violations[0].path == outside
    db_files = [e for e in events if e.kind == "db_file"]
    assert db_files and db_files[0].service == "sqlite"
    assert db_files[0].reason == "read_write"
