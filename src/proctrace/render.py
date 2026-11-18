"""Plain-text, JSONL, and snapshot rendering."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional, TextIO

from .model import Event
from .utils import format_clock, format_datetime, head_fit, sanitize

NONFILE_KINDS = {"socket", "pipe", "anon", "other"}


def is_visible_fd(kind: str, show_nonfile: bool) -> bool:
    return show_nonfile or kind not in NONFILE_KINDS


def is_visible_event(event: Event, show_nonfile: bool) -> bool:
    if event.kind in (
        "warn",
        "alert",
        "violation",
        "net_open",
        "net_change",
        "net_close",
        "db_connect",
        "db_change",
        "db_close",
        "db_file",
        "db_query",
        "process_start",
        "process_exit",
    ):
        return True
    if event.file_kind and not is_visible_fd(event.file_kind, show_nonfile):
        return False
    return True


def _short(text: str, width: int) -> str:
    return head_fit(sanitize(text), width)


def event_line(event: Event, show_nonfile: bool = True) -> str:
    if not is_visible_event(event, show_nonfile):
        return ""
    clock = format_clock(event.ts)
    if event.kind == "warn":
        return "%s WARN     %-16s %s" % (
            clock,
            "proctrace",
            sanitize(event.detail),
        )
    name = _short(event.name, 16)
    if event.kind == "alert":
        victim = "%d %s" % (event.victim_pid or 0, _short(event.victim_name, 16))
        location = sanitize(event.path) if event.path else ""
        return "%s ALERT    %-7d %-16s -> %-22s via=%-6s %s" % (
            clock,
            event.pid,
            name,
            victim,
            event.via or "?",
            location,
        )
    if event.kind in ("net_open", "net_change", "net_close", "db_connect", "db_change", "db_close"):
        net = event.net or {}
        label = "DB" if event.kind.startswith("db_") else "NET"
        remote = str(net.get("remote", "") or "-")
        local = str(net.get("local", "") or "-")
        service = str(net.get("service", "") or "")
        return "%s %-3s    %-7d %-16s fd=%-4s %-5s %s -> %s %s" % (
            clock,
            label,
            event.pid,
            name,
            "" if event.fd is None else event.fd,
            str(net.get("proto", "") or "-"),
            sanitize(local),
            sanitize(remote),
            sanitize(service),
        )
    if event.kind == "db_query":
        db = event.db or {}
        return "%s DB_QUERY %-6d %-16s %-9s %-6s %-9s %s" % (
            clock,
            event.pid,
            name,
            str(db.get("system", "") or "db"),
            str(event.severity or "low"),
            str(db.get("operation", "") or "?"),
            sanitize(str(db.get("sql", "") or event.detail)),
        )
    if event.kind == "db_file":
        return "%s DB_FILE  %-7d %-16s fd=%-4s %-2s %-9s %-10s %s" % (
            clock,
            event.pid,
            name,
            "" if event.fd is None else event.fd,
            event.mode or "-",
            event.service or "db",
            event.reason or "?",
            sanitize(event.path),
        )
    if event.kind == "violation":
        return "%s VIOLATION %-6d %-16s fd=%-4s %-2s %-18s %s" % (
            clock,
            event.pid,
            name,
            "" if event.fd is None else event.fd,
            event.mode or "-",
            event.reason or "path",
            sanitize(event.path),
        )
    if event.kind in ("process_start", "process_exit"):
        detail = sanitize(event.detail)
        return "%s %-8s %-7d %-16s %s" % (
            clock,
            event.label(),
            event.pid,
            name,
            detail,
        )
    fd = "" if event.fd is None else str(event.fd)
    mode = event.mode or "-"
    path = event.path or event.detail
    if event.kind == "close":
        path = event.path
    if event.kind == "change" and event.detail:
        path = event.detail
    return "%s %-8s %-7d %-16s fd=%-4s %-2s %s" % (
        clock,
        event.label(),
        event.pid,
        name,
        fd,
        mode,
        sanitize(path),
    )


def write_event(event: Event, show_nonfile: bool = True, stream: Optional[TextIO] = None) -> None:
    line = event_line(event, show_nonfile)
    if line:
        (stream or sys.stdout).write(line + "\n")


def write_json(obj: Any, stream: Optional[TextIO] = None) -> None:
    (stream or sys.stdout).write(json.dumps(obj, ensure_ascii=False) + "\n")


def write_jsonl_event(event: Event, stream: Optional[TextIO] = None) -> None:
    write_json(event.to_dict(), stream=stream)


def human_snapshot(data: Dict[str, Any], show_nonfile: bool = False) -> str:
    lines: List[str] = []
    lines.append(
        "proctrace snapshot  %s  backend=%s"
        % (format_datetime(float(data.get("generated_at", 0))), data.get("backend", "?"))
    )
    target = data.get("target_pid", "?")
    notes = data.get("notes") or []
    for note in notes:
        lines.append("note: %s" % sanitize(note))
    if data.get("audit") and data.get("audit") != "audit=off":
        lines.append("audit: %s" % sanitize(str(data["audit"])))
    stats = data.get("stats") or {}
    lines.append(
        "target=%s  processes=%s  fds=%s  alerts=%s"
        % (target, stats.get("processes", "?"), stats.get("fds", "?"), stats.get("alerts", "?"))
    )
    lines.append("")

    for proc in data.get("processes", []):
        markers = []
        if proc.get("protected"):
            markers.append("PROTECTED")
        if proc.get("excluded"):
            markers.append("EXCLUDED")
        if proc.get("error"):
            markers.append("ERROR: %s" % proc["error"])
        suffix = ("  [" + ", ".join(markers) + "]") if markers else ""
        lines.append(
            "%s%7d %-24s ppid=%-7s fds=%s%s"
            % (
                "  " * int(proc.get("depth", 0)),
                int(proc.get("pid", 0)),
                sanitize(proc.get("name") or ""),
                proc.get("ppid", 0),
                proc.get("fd_count", 0),
                suffix,
            )
        )
        if proc.get("exe"):
            lines.append("         exe: %s" % sanitize(proc["exe"]))
        files = proc.get("files") or []
        for file_info in files:
            if not is_visible_fd(file_info.get("kind", "file"), show_nonfile):
                continue
            mode = file_info.get("mode") or "-"
            deleted = " (deleted)" if file_info.get("deleted") else ""
            lines.append(
                "         fd=%-4s %-2s %s%s"
                % (
                    file_info.get("fd", "?"),
                    mode,
                    sanitize(file_info.get("path", "")),
                    deleted,
                )
            )
    connections = data.get("connections") or []
    if connections:
        lines.append("")
        lines.append("network:")
        for conn in connections:
            service = " %s" % conn["service"] if conn.get("service") else ""
            lines.append(
                "  pid=%-7s fd=%-4s %-5s %s -> %s %s%s"
                % (
                    conn.get("pid", "?"),
                    conn.get("fd", "?"),
                    conn.get("proto", "?"),
                    sanitize(conn.get("local", "") or "-"),
                    sanitize(conn.get("remote", "") or "-"),
                    conn.get("status", ""),
                    service,
                )
            )
    alerts = data.get("alerts") or []
    violations = data.get("violations") or []
    if alerts:
        lines.append("")
        lines.append("alerts:")
        for alert in alerts:
            lines.append(
                "  ALERT %s(%d) -> %s(%s) via=%s %s"
                % (
                    sanitize(alert.get("name", "")),
                    alert.get("pid", 0),
                    sanitize(alert.get("victim_name", "")),
                    alert.get("victim_pid", 0),
                    alert.get("via", ""),
                    sanitize(alert.get("path", "")),
                )
            )
    database_events = data.get("database_events") or []
    if database_events:
        lines.append("")
        lines.append("database events:")
        for event in database_events:
            net = event.get("net") or {}
            db = event.get("db") or {}
            detail = (
                db.get("sql")
                or event.get("path")
                or ("%s -> %s" % (net.get("local", ""), net.get("remote", "")))
            )
            lines.append(
                "  %-12s pid=%-7s %-10s %-6s %s"
                % (
                    event.get("kind", "db"),
                    event.get("pid", "?"),
                    event.get("service", ""),
                    db.get("risk", ""),
                    sanitize(detail),
                )
            )
    if violations:
        lines.append("")
        lines.append("violations:")
        for violation in violations:
            lines.append(
                "  VIOLATION %s(%s) fd=%s %-18s %s"
                % (
                    sanitize(violation.get("name", "")),
                    violation.get("pid", 0),
                    violation.get("fd", "?"),
                    violation.get("reason", "path"),
                    sanitize(violation.get("path", "")),
                )
            )
    return "\n".join(lines)


def snapshot_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)
