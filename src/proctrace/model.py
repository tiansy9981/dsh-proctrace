"""Core data structures."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class FdInfo:
    """One open file descriptor.

    ``kind`` is one of: file, dir, socket, pipe, anon, other.
    ``target_pid`` is filled for Linux pidfds (and procfs paths are recognised
    from ``path`` independently).
    """

    fd: int
    path: str
    kind: str = "file"
    mode: str = ""
    deleted: bool = False
    target_pid: Optional[int] = None
    detail: str = ""

    def identity(self) -> tuple:
        # "deleted" is included because macOS/lsof may report the suffix while
        # the kernel object is still the same; keeping it stable is harmless.
        return (self.path, self.kind, self.mode, self.deleted, self.target_pid)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "fd": self.fd,
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
        }
        if self.deleted:
            data["deleted"] = True
        if self.target_pid is not None:
            data["target_pid"] = self.target_pid
        if self.detail:
            data["detail"] = self.detail
        return data


@dataclass
class Event:
    """A single monitor event, suitable for TUI/JSONL logging."""

    ts: float
    kind: str
    pid: int
    name: str = ""
    ppid: int = 0
    fd: Optional[int] = None
    path: str = ""
    mode: str = ""
    file_kind: str = ""
    initial: bool = False
    reason: str = ""
    severity: str = ""
    service: str = ""
    net: Optional[Dict[str, Any]] = None
    db: Optional[Dict[str, Any]] = None
    victim_pid: Optional[int] = None
    victim_name: str = ""
    via: str = ""
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "ts": round(self.ts, 6),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts))
            + ".%03d" % (int(self.ts * 1000) % 1000),
            "kind": self.kind,
            "pid": self.pid,
            "name": self.name,
            "ppid": self.ppid,
        }
        if self.fd is not None:
            data["fd"] = self.fd
        if self.path:
            data["path"] = self.path
        if self.mode:
            data["mode"] = self.mode
        if self.file_kind:
            data["file_kind"] = self.file_kind
        if self.initial:
            data["initial"] = True
        if self.reason:
            data["reason"] = self.reason
        if self.severity:
            data["severity"] = self.severity
        if self.service:
            data["service"] = self.service
        if self.net:
            data["net"] = self.net
        if self.db:
            data["db"] = self.db
        if self.victim_pid is not None:
            data["victim_pid"] = self.victim_pid
        if self.victim_name:
            data["victim_name"] = self.victim_name
        if self.via:
            data["via"] = self.via
        if self.detail:
            data["detail"] = self.detail
        return data

    def label(self) -> str:
        if self.kind == "alert":
            return "ALERT"
        if self.kind == "violation":
            return "VIOLATION"
        if self.kind == "db_query":
            return "DB_QUERY"
        if self.kind in ("db_connect", "db_change", "db_close", "db_file"):
            return "DB"
        if self.kind in ("net_open", "net_change", "net_close"):
            return "NET"
        if self.kind == "process_start":
            return "START"
        if self.kind == "process_exit":
            return "EXIT"
        if self.kind == "change":
            return "CHANGE"
        if self.kind == "warn":
            return "WARN"
        return self.kind.upper()


@dataclass
class ProcessInfo:
    """A process in the monitored tree (or in the policy scan)."""

    pid: int
    ppid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: List[str] = field(default_factory=list)
    uid: Optional[int] = None
    create_time: float = 0.0
    depth: int = 0
    protected: bool = False
    excluded: bool = False
    fd_count: int = 0
    error: str = ""
    started: bool = False

    def to_dict(self, include_files: bool = False, files: Optional[List[FdInfo]] = None) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": list(self.cmdline),
            "depth": self.depth,
            "protected": self.protected,
            "excluded": self.excluded,
            "fd_count": self.fd_count,
        }
        if self.create_time:
            data["create_time"] = self.create_time
        if self.error:
            data["error"] = self.error
        if include_files:
            data["files"] = [f.to_dict() for f in (files or [])]
        return data


@dataclass
class MonitorStats:
    started_at: float = field(default_factory=time.time)
    polls: int = 0
    scan_seconds: float = 0.0
    last_scan_seconds: float = 0.0
    max_scan_seconds: float = 0.0
    events: int = 0
    process_count: int = 0
    fd_count: int = 0
    alerts: int = 0
    errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uptime": round(time.time() - self.started_at, 3),
            "polls": self.polls,
            "last_scan_ms": round(self.last_scan_seconds * 1000, 2),
            "max_scan_ms": round(self.max_scan_seconds * 1000, 2),
            "avg_scan_ms": round(
                (self.scan_seconds / self.polls * 1000) if self.polls else 0.0, 2
            ),
            "events": self.events,
            "processes": self.process_count,
            "fds": self.fd_count,
            "alerts": self.alerts,
            "errors": self.errors,
        }
