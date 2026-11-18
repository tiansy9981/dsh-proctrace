import os

from proctrace.config import AuditConfig
from proctrace.pathpolicy import PathAudit


def make_audit(tmp_path, **kwargs):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    cfg = AuditConfig(
        enabled=True,
        workspaces=[str(ws)],
        use_defaults=False,
        outside_workspace=True,
        **kwargs
    )
    return ws, PathAudit(cfg, platform="linux")


def test_workspace_and_outside(tmp_path):
    ws, audit = make_audit(tmp_path)
    assert audit.evaluate(str(ws / "a.py")) is None
    verdict = audit.evaluate(str(tmp_path / "outside.txt"))
    assert verdict is not None
    assert verdict.reason == "outside_workspace"


def test_deny_inside_workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    audit = PathAudit(
        AuditConfig(
            enabled=True,
            workspaces=[str(ws)],
            use_defaults=False,
            deny_paths=[str(ws / ".env")],
        ),
        platform="linux",
    )
    assert audit.evaluate(str(ws / ".env")).reason == "denied_path"
    assert audit.evaluate(str(ws / "main.py")) is None


def test_allow_overrides_outside(tmp_path):
    outside = tmp_path / "shared"
    outside.mkdir()
    ws, audit = make_audit(tmp_path, allow_paths=[str(outside / "**")])
    assert audit.evaluate(str(outside / "lib.py")) is None
    assert audit.evaluate(str(tmp_path / "other.txt")).reason == "outside_workspace"


def test_ignore_overrides_deny(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    audit = PathAudit(
        AuditConfig(
            enabled=True,
            workspaces=[str(ws)],
            use_defaults=False,
            deny_paths=[str(ws / "**")],
            ignore_paths=[str(ws / "allowed.txt")],
        ),
        platform="linux",
    )
    assert audit.evaluate(str(ws / "allowed.txt")) is None
    assert audit.evaluate(str(ws / "blocked.txt")).reason == "denied_path"


def test_default_sensitive_paths(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    cfg = AuditConfig(enabled=True, workspaces=[str(ws)], use_defaults=True)
    audit = PathAudit(cfg, platform="linux")
    ssh = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")
    assert audit.evaluate(ssh).reason == "denied_path"
    assert audit.evaluate("/usr/lib/libc.so") is None
    assert audit.evaluate(str(ws / ".env")).reason == "denied_path"


def test_no_outside_mode(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    cfg = AuditConfig(
        enabled=True,
        workspaces=[str(ws)],
        use_defaults=False,
        outside_workspace=False,
    )
    audit = PathAudit(cfg, platform="linux")
    assert audit.evaluate(str(tmp_path / "outside.txt")) is None


def test_non_file_and_disabled(tmp_path):
    ws, audit = make_audit(tmp_path)
    assert audit.evaluate("socket:[123]") is None
    assert audit.evaluate(str(ws / "x"), kind="socket") is None
    cfg = AuditConfig(enabled=False, workspaces=[str(ws)])
    assert PathAudit(cfg).evaluate(str(tmp_path / "outside")) is None
