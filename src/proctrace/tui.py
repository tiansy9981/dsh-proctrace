"""Dependency-free ANSI live view.

The system Python 3.9 curses module on macOS 13 is unstable (it can SIGSEGV
after initscr), so proctrace uses a small raw-terminal renderer instead.  It
works on macOS and Linux with any Python 3.9+ and has no ncurses dependency.
"""

from __future__ import annotations

import json
import os
import select
import signal
import sys
import time
from collections import deque
from typing import Deque, List, Optional, Sequence, TextIO, Tuple

from .engine import Monitor, TargetGone, TargetRejected
from .model import Event, ProcessInfo
from .render import is_visible_event, is_visible_fd, write_jsonl_event
from .utils import format_clock, head_fit, sanitize, tail_fit

HELP_LINES = [
    "proctrace keys",
    "",
    "  q            quit",
    "  space        pause / resume scanning",
    "  up/down j/k  select process",
    "  enter        filter event list to selected pid",
    "  esc          clear filters",
    "  f            cycle filter: all -> opens -> alerts",
    "  /            text filter (path, name, detail)",
    "  [ ]          scroll event history older / newer",
    "  c            clear event list",
    "  e            export snapshot JSON to current directory",
    "  v            toggle event stream / current files of selected pid",
    "  n            toggle event stream / network connections of selected pid",
    "  a            toggle sockets/pipes/anon in the list",
    "  + -          slower / faster polling",
    "  ?            this help",
    "",
    "Protected processes are marked P and never scanned.",
]

ALT_ENTER = "\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J"
ALT_EXIT = "\x1b[0m\x1b[?25h\x1b[?1049l"
CLEAR_LINE = "\x1b[2K"
C_RESET = "\x1b[0m"
C_BOLD = "\x1b[1m"
C_DIM = "\x1b[2m"
C_INVERSE = "\x1b[7m"
C_RED = "\x1b[31;1m"
C_GREEN = "\x1b[32m"
C_YELLOW = "\x1b[33m"
C_CYAN = "\x1b[36m"
C_MAGENTA = "\x1b[35m"


def paint(code: str, text: str) -> str:
    if not code:
        return text
    return code + text + C_RESET


class TUI:
    def __init__(
        self,
        monitor: Monitor,
        target_label: str,
        notes: Optional[Sequence[str]] = None,
        show_nonfile: Optional[bool] = None,
        log_handle: Optional[TextIO] = None,
    ) -> None:
        self.monitor = monitor
        self.target_label = target_label
        self.notes = list(notes or [])
        self.show_nonfile = (
            monitor.config.show_nonfile if show_nonfile is None else show_nonfile
        )
        self.log_handle = log_handle
        self.events: Deque[Event] = deque(maxlen=monitor.config.max_events)
        self.interval = monitor.config.interval
        self.paused = False
        self.running = True
        self.exit_code = 0
        self.filter_mode = "all"
        self.view_mode = "events"
        self.filter_pid: Optional[int] = None
        self.text_filter = ""
        self.ev_scroll = 0
        self.selected_pid: Optional[int] = self.monitor.root_pid
        self._proc_index: Optional[int] = None
        self._next_poll = 0.0
        self._last_draw = 0.0
        self._dirty = True
        self._status = ""
        self._status_until = 0.0
        self._fatal = ""
        self._alert_total = 0
        self._out = sys.stdout
        self._in_fd = -1
        self._out_fd = -1
        self._keybuf = b""
        self._last_size: Tuple[int, int] = (0, 0)
        self._old_handlers = {}

    # ------------------------------------------------------------------ run
    def run(self) -> int:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return 2
        try:
            import termios
            import tty
        except ImportError:
            return 2
        self._in_fd = sys.stdin.fileno()
        self._out_fd = sys.stdout.fileno()
        try:
            old_attrs = termios.tcgetattr(self._in_fd)
        except termios.error:
            return 2
        try:
            tty.setraw(self._in_fd)
        except termios.error:
            return 2
        try:
            self._install_signals()
            self._out.write(ALT_ENTER)
            self._out.flush()
            self._poll_once()
            self._next_poll = time.monotonic() + self.interval
            self._loop()
        except KeyboardInterrupt:
            self.exit_code = 130
        finally:
            try:
                termios.tcsetattr(self._in_fd, termios.TCSADRAIN, old_attrs)
            except termios.error:
                pass
            try:
                self._out.write(ALT_EXIT)
                self._out.flush()
            except OSError:
                pass
            self._restore_signals()
        return self.exit_code

    def _install_signals(self) -> None:
        def stop(signum, frame):
            self.running = False

        def resize(signum, frame):
            self._dirty = True

        for sig, handler in (
            (signal.SIGTERM, stop),
            (signal.SIGHUP, stop),
            (signal.SIGINT, stop),
            (signal.SIGWINCH, resize),
        ):
            try:
                self._old_handlers[sig] = signal.signal(sig, handler)
            except (ValueError, OSError):
                pass

    def _restore_signals(self) -> None:
        for sig, handler in self._old_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        self._old_handlers = {}

    def _loop(self) -> None:
        self._render()
        while self.running:
            size = self._size()
            if size != self._last_size:
                self._dirty = True
            now = time.monotonic()
            if (
                not self.paused
                and not self._fatal
                and not self.monitor.target_gone
                and now >= self._next_poll
            ):
                self._poll_once()
                self._next_poll = time.monotonic() + self.interval
            key = self._read_key(0.05)
            if key is not None:
                self._handle_key(key)
            if self._dirty or time.monotonic() - self._last_draw >= 0.25:
                self._render()

    # ---------------------------------------------------------------- polling
    def _poll_once(self) -> None:
        if self.monitor.target_gone or self._fatal:
            return
        try:
            events = self.monitor.poll()
        except TargetRejected as exc:
            self._fatal = str(exc)
            self._set_status(self._fatal, long=True)
            return
        except TargetGone:
            self.monitor.target_gone = True
            return
        except Exception as exc:
            self._fatal = "扫描失败: %s: %s" % (type(exc).__name__, exc)
            self._set_status(self._fatal, long=True)
            return
        for event in events:
            self.events.append(event)
            if event.kind in ("alert", "violation") or (
                event.kind == "db_query" and event.severity == "high"
            ):
                self._alert_total += 1
            if self.log_handle is not None:
                write_jsonl_event(event, stream=self.log_handle)
        if self.log_handle is not None:
            self.log_handle.flush()
        if self.monitor.target_gone:
            if self.monitor.db_audit_source is not None:
                time.sleep(0.1)
                for event in self.monitor.drain_supplemental():
                    self.events.append(event)
                    if event.kind in ("alert", "violation") or (
                        event.kind == "db_query" and event.severity == "high"
                    ):
                        self._alert_total += 1
                    if self.log_handle is not None:
                        write_jsonl_event(event, stream=self.log_handle)
                if self.log_handle is not None:
                    self.log_handle.flush()
            self._set_status("target exited; showing final state", long=True)
        self._dirty = True

    # ---------------------------------------------------------------- drawing
    def _size(self) -> Tuple[int, int]:
        try:
            size = os.get_terminal_size(self._out_fd)
            return (size.columns, size.lines)
        except OSError:
            return (80, 24)

    def _render(self) -> None:
        width, height = self._size()
        self._last_size = (width, height)
        lines = self.build_screen(width, height)
        self._write_screen(lines)
        self._last_draw = time.monotonic()
        self._dirty = False

    def _write_screen(self, lines: Sequence[str]) -> None:
        out = ["\x1b[H"]
        for index, line in enumerate(lines):
            out.append(CLEAR_LINE)
            out.append(line)
            if index != len(lines) - 1:
                out.append("\r\n")
        try:
            self._out.write("".join(out))
            self._out.flush()
        except OSError:
            self.running = False

    def build_screen(self, width: int, height: int) -> List[str]:
        if height < 14 or width < 64:
            return [
                paint(C_RED, head_fit("proctrace: terminal too small (need at least 64x14)", width)),
                "",
                paint(C_DIM, "q quit"),
            ]
        lines: List[str] = []
        lines.append(self._header_line(width))
        lines.append(self._stats_line(width))
        body_top = 2
        body_height = height - body_top - 2
        left_width = min(max(38, int(width * 0.38)), 58)
        if width < 90:
            left_width = max(30, int(width * 0.42))
        right_width = max(10, width - left_width - 2)
        left_lines = self._process_lines(body_height, left_width)
        if self.view_mode == "files":
            right_lines = self._file_lines(body_height, right_width)
        elif self.view_mode == "net":
            right_lines = self._net_lines(body_height, right_width)
        else:
            right_lines = self._event_lines(body_height, right_width)
        for index in range(body_height):
            left_text, left_color = left_lines[index] if index < len(left_lines) else ("", "")
            right_text, right_color = right_lines[index] if index < len(right_lines) else ("", "")
            left_text = left_text.ljust(left_width)[:left_width]
            right_text = right_text[:right_width]
            composed = (
                paint(left_color, left_text)
                + paint(C_DIM, "|")
                + paint(right_color, right_text)
            )
            lines.append(composed)
        lines.append(self._keys_line(width))
        lines.append(self._status_line(width))
        return lines

    def _header_line(self, width: int) -> str:
        stats = self.monitor.stats
        state = "PAUSED" if self.paused else ("EXITED" if self.monitor.target_gone else "LIVE")
        if self._fatal:
            state = "ERROR"
        if self.monitor.path_audit is not None and self.monitor.path_audit.enabled:
            state += "/AUDIT"
        head = "proctrace  %s  target=%s  backend=%s  %.2fs" % (
            state,
            self.target_label,
            self.monitor.collector.name,
            self.interval,
        )
        return paint(C_CYAN + C_BOLD, head_fit(sanitize(head), width - 1))

    def _stats_line(self, width: int) -> str:
        stats = self.monitor.stats
        filt = self.filter_mode
        if self.filter_pid is not None:
            filt += " pid=%d" % self.filter_pid
        if self.text_filter:
            filt += " text=%r" % self.text_filter
        line = "procs=%-4d fds=%-4d events=%-5d alerts=%-4d scan=%.1fms (max %.1f)  filter=%s" % (
            stats.process_count,
            stats.fd_count,
            len(self.events),
            self._alert_total,
            stats.last_scan_seconds * 1000,
            stats.max_scan_seconds * 1000,
            filt,
        )
        return paint(C_DIM, head_fit(sanitize(line), width - 1))

    def _process_lines(self, height: int, width: int) -> List[Tuple[str, str]]:
        procs = self.monitor.process_list()
        if self.selected_pid is not None:
            for index, proc in enumerate(procs):
                if proc.pid == self.selected_pid:
                    self._proc_index = index
                    break
            else:
                self._proc_index = None
        if self._proc_index is None and procs:
            self._proc_index = 0
            self.selected_pid = procs[0].pid
        header = "%-7s %-6s %-*s %4s" % (
            "PID",
            "PPID",
            max(8, width - 21),
            "NAME",
            "FD",
        )
        lines: List[Tuple[str, str]] = [(head_fit(header, width), C_DIM)]
        rows = height - 1
        if rows <= 0:
            return lines
        selected = self._proc_index or 0
        start = max(0, selected - rows + 1)
        for row, proc in enumerate(procs[start : start + rows]):
            selected_row = (start + row) == selected
            lines.append(self._process_row(proc, width, selected_row))
        return lines

    def _process_row(self, proc: ProcessInfo, width: int, selected: bool) -> Tuple[str, str]:
        name_width = max(8, width - 21)
        indent = "  " * min(proc.depth, 8)
        marker = "P " if proc.protected else ("x " if proc.excluded else "  ")
        if proc.error:
            marker = "! "
        name = head_fit(indent + marker + sanitize(proc.name or "?"), name_width)
        line = "%-7d %-6d %-*s %4d" % (
            proc.pid,
            proc.ppid,
            name_width,
            name,
            proc.fd_count,
        )
        color = ""
        if proc.protected:
            color = C_RED
        elif proc.excluded or proc.error:
            color = C_DIM
        if selected:
            color = C_INVERSE + (C_BOLD if proc.protected else "")
        return (head_fit(line, width), color)

    def _filtered_events(self) -> List[Event]:
        result = []
        text = self.text_filter.lower()
        for event in self.events:
            if not is_visible_event(event, self.show_nonfile):
                continue
            if self.filter_mode == "opens" and event.kind not in ("open", "change", "close"):
                continue
            if self.filter_mode == "alerts" and event.kind not in ("alert", "violation"):
                if not (event.kind == "db_query" and event.severity in ("high", "medium")):
                    continue
            if self.filter_pid is not None and event.pid != self.filter_pid:
                continue
            if text:
                haystack = " ".join(
                    [
                        event.path or "",
                        event.name or "",
                        event.detail or "",
                        event.reason or "",
                        event.victim_name or "",
                    ]
                ).lower()
                if text not in haystack:
                    continue
            result.append(event)
        return result

    def _file_lines(self, height: int, width: int) -> List[Tuple[str, str]]:
        proc = self.monitor.processes.get(self.selected_pid) if self.selected_pid else None
        title = "CURRENT FILES"
        if proc is not None:
            title += "  pid=%d %s" % (proc.pid, sanitize(proc.name or "?"))
        lines: List[Tuple[str, str]] = [(head_fit(title, width), C_DIM)]
        rows = height - 1
        if rows <= 0:
            return lines
        if self.selected_pid is None:
            lines.append(("no process selected", C_DIM))
            return lines
        if proc is not None and proc.protected:
            lines.append(("protected process: fd table intentionally not read", C_RED))
            return lines
        if proc is not None and proc.excluded:
            lines.append(("excluded process: fd table intentionally not read", C_DIM))
            return lines
        files = [
            f
            for f in self.monitor.files_for(self.selected_pid)
            if is_visible_fd(f.kind, self.show_nonfile)
        ]
        if not files:
            lines.append(("no open files observed (baseline may be hidden)", C_DIM))
            return lines
        for file_info in files[:rows]:
            prefix = "%4d  %-3s " % (file_info.fd, file_info.mode or "-")
            path_width = max(4, width - len(prefix) - 20)
            text = prefix + tail_fit(sanitize(file_info.path), path_width)
            verdict = None
            if (
                self.monitor.path_audit is not None
                and (file_info.fd not in (0, 1, 2) or self.monitor.path_audit.include_stdio)
            ):
                verdict = self.monitor.path_audit.evaluate(file_info.path, file_info.kind)
            if verdict is not None:
                text += "  [%s]" % verdict.reason
                color = C_RED
            else:
                color = C_GREEN
            lines.append((head_fit(text, width), color))
        return lines

    def _net_lines(self, height: int, width: int) -> List[Tuple[str, str]]:
        proc = self.monitor.processes.get(self.selected_pid) if self.selected_pid else None
        title = "NETWORK"
        if proc is not None:
            title += "  pid=%d %s" % (proc.pid, sanitize(proc.name or "?"))
        lines: List[Tuple[str, str]] = [(head_fit(title, width), C_DIM)]
        rows = height - 1
        if rows <= 0:
            return lines
        if self.monitor.network_monitor is None or not self.monitor.network_monitor.enabled:
            lines.append(("network monitoring is disabled (--network)", C_DIM))
            return lines
        if self.selected_pid is None:
            lines.append(("no process selected", C_DIM))
            return lines
        connections = self.monitor.network_monitor.connections_for(self.selected_pid)
        if not connections:
            lines.append(("no active network connections", C_DIM))
            return lines
        for conn in connections[:rows]:
            service = "  [%s]" % conn.service if conn.service else ""
            text = "%-5s %-22s -> %-22s %-10s%s" % (
                conn.proto,
                sanitize(conn.local or "-"),
                sanitize(conn.remote or "-"),
                conn.status,
                service,
            )
            color = C_MAGENTA if conn.service else C_CYAN
            lines.append((head_fit(text, width), color))
        return lines

    def _event_lines(self, height: int, width: int) -> List[Tuple[str, str]]:
        header = "TIME      PID    PROCESS          EVENT  DETAIL"
        lines: List[Tuple[str, str]] = [(head_fit(header, width), C_DIM)]
        rows = height - 1
        if rows <= 0:
            return lines
        events = self._filtered_events()
        max_scroll = max(0, len(events) - rows)
        end = len(events) - min(self.ev_scroll, max_scroll)
        start = max(0, end - rows)
        for event in events[start:end]:
            lines.append((self._event_text(event, width), self._event_color(event)))
        return lines

    def _event_text(self, event: Event, width: int) -> str:
        clock = format_clock(event.ts, milliseconds=False)
        name = head_fit(sanitize(event.name or "?"), 14)
        if event.kind == "warn":
            return head_fit("%s WARN  %s" % (clock, sanitize(event.detail)), width)
        if event.kind == "db_query":
            db = event.db or {}
            prefix = "%s %-6d %-14s DB_QUERY %-6s %-6s " % (
                clock,
                event.pid,
                name,
                str(db.get("system", "") or "db"),
                str(event.severity or "low"),
            )
            path_width = max(4, width - len(prefix))
            return head_fit(
                prefix + tail_fit(sanitize(str(db.get("sql", "") or event.detail)), path_width),
                width,
            )
        if event.kind in ("net_open", "net_change", "net_close", "db_connect", "db_change", "db_close"):
            net = event.net or {}
            label = "DB" if event.kind.startswith("db_") else "NET"
            service = str(net.get("service", "") or "")
            prefix = "%s %-6d %-14s %-3s " % (clock, event.pid, name, label)
            detail = "%s %s -> %s" % (
                str(net.get("proto", "") or "?"),
                sanitize(str(net.get("local", "") or "-")),
                sanitize(str(net.get("remote", "") or "-")),
            )
            if service:
                detail += " [%s]" % sanitize(service)
            path_width = max(4, width - len(prefix))
            return head_fit(prefix + tail_fit(detail, path_width), width)
        if event.kind == "db_file":
            prefix = "%s %-6d %-14s DB_FILE %-3s " % (
                clock,
                event.pid,
                name,
                event.mode or "-",
            )
            detail = "%s %s %s" % (
                event.service or "db",
                event.reason or "?",
                sanitize(event.path),
            )
            path_width = max(4, width - len(prefix))
            return head_fit(prefix + tail_fit(detail, path_width), width)
        if event.kind == "violation":
            short = "outside" if event.reason == "outside_workspace" else "deny"
            prefix = "%s %-6d %-14s VIOL %-8s " % (
                clock,
                event.pid,
                name,
                short,
            )
            path_width = max(4, width - len(prefix))
            return head_fit(
                prefix + tail_fit(sanitize(event.path), path_width),
                width,
            )
        if event.kind == "alert":
            prefix = "%s %-6d %-14s ALERT -> %d %s" % (
                clock,
                event.pid,
                name,
                event.victim_pid or 0,
                head_fit(sanitize(event.victim_name or "?"), 10),
            )
            path_width = max(4, width - len(prefix) - 1)
            return head_fit(
                "%s %s" % (prefix, tail_fit(sanitize(event.path or event.detail), path_width)),
                width,
            )
        if event.kind in ("process_start", "process_exit"):
            return head_fit(
                "%s %-6d %-14s %-6s %s"
                % (clock, event.pid, name, event.label(), sanitize(event.detail)),
                width,
            )
        fd = "" if event.fd is None else str(event.fd)
        prefix = "%s %-6d %-14s %-6s %-4s " % (
            clock,
            event.pid,
            name,
            event.label(),
            fd,
        )
        path_width = max(4, width - len(prefix))
        path = event.detail if event.kind == "change" and event.detail else event.path
        return prefix + tail_fit(sanitize(path), path_width)

    def _event_color(self, event: Event) -> str:
        if event.kind in ("alert", "violation"):
            return C_RED
        if event.kind == "db_query":
            if event.severity == "high":
                return C_RED
            if event.severity == "medium":
                return C_YELLOW
            return C_MAGENTA
        if event.kind.startswith("db_"):
            return C_MAGENTA
        if event.kind.startswith("net_"):
            return C_CYAN
        if event.kind == "read":
            return C_GREEN
        if event.kind == "write":
            return C_YELLOW
        if event.kind == "warn":
            return C_YELLOW
        if event.kind in ("open", "process_start"):
            return C_GREEN
        if event.kind == "change":
            return C_CYAN
        if event.kind in ("close", "process_exit"):
            return C_DIM
        return ""

    def _keys_line(self, width: int) -> str:
        keys = (
            "q quit  space pause  v files  n net  f filter  / search  enter pid  "
            "[ ] scroll  c clear  e export  a types  +/- rate  ? help"
        )
        return paint(C_DIM, head_fit(keys, width - 1))

    def _status_line(self, width: int) -> str:
        now = time.time()
        color = C_DIM
        if self._status and (self._status_until == 0 or now < self._status_until):
            message = self._status
            color = C_YELLOW
        elif self.monitor.target_gone:
            message = "target exited - final state shown; q to quit"
            color = C_RED
        elif self._fatal:
            message = self._fatal
            color = C_RED
        elif self.notes:
            message = self.notes[0]
        else:
            message = "protected processes are marked P and never scanned"
        return paint(color, head_fit(sanitize(message), width - 1))

    # ------------------------------------------------------------------ input
    def _read_key(self, timeout: Optional[float]) -> Optional[str]:
        if self._keybuf:
            return self._parse_key()
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except (OSError, ValueError):
            self.running = False
            return None
        if not ready:
            return None
        try:
            data = os.read(self._in_fd, 64)
        except OSError:
            self.running = False
            return None
        if not data:
            self.running = False
            return None
        self._keybuf += data
        return self._parse_key()

    def _parse_key(self) -> Optional[str]:
        buf = self._keybuf
        if not buf:
            return None
        if buf[0] == 27:
            # Try to complete an escape sequence (arrow keys arrive as ESC [ A).
            if len(buf) < 3:
                ready, _, _ = select.select([sys.stdin], [], [], 0.01)
                if ready:
                    try:
                        buf += os.read(self._in_fd, 8)
                    except OSError:
                        pass
                    self._keybuf = buf
            if buf.startswith(b"\x1b[A") or buf.startswith(b"\x1bOA"):
                self._keybuf = buf[3:]
                return "up"
            if buf.startswith(b"\x1b[B") or buf.startswith(b"\x1bOB"):
                self._keybuf = buf[3:]
                return "down"
            if buf.startswith(b"\x1b[5~"):
                self._keybuf = buf[4:]
                return "["
            if buf.startswith(b"\x1b[6~"):
                self._keybuf = buf[4:]
                return "]"
            self._keybuf = buf[1:]
            return "esc"
        byte = buf[0]
        self._keybuf = buf[1:]
        if byte in (10, 13):
            return "enter"
        if byte in (8, 127):
            return "backspace"
        if byte == 3:
            return "ctrl-c"
        if byte == 12:
            return "redraw"
        if 32 <= byte < 127:
            return chr(byte)
        return ""

    def _handle_key(self, ch: str) -> None:
        if ch in ("q", "Q", "ctrl-c"):
            self.running = False
            return
        if ch == " ":
            self.paused = not self.paused
            if not self.paused:
                self._next_poll = time.monotonic()
            self._set_status("paused" if self.paused else "resumed", short=True)
            return
        if ch in ("up", "k"):
            self._move_selection(-1)
            return
        if ch in ("down", "j"):
            self._move_selection(1)
            return
        if ch == "enter":
            if self.selected_pid is not None:
                self.filter_pid = self.selected_pid
                self.filter_mode = "pid"
                self.ev_scroll = 0
                self._set_status("filtering pid %d" % self.selected_pid, short=True)
            return
        if ch == "esc":
            self.filter_mode = "all"
            self.filter_pid = None
            self.text_filter = ""
            self.ev_scroll = 0
            self._set_status("filters cleared", short=True)
            return
        if ch == "f":
            cycle = {"all": "opens", "opens": "alerts", "alerts": "all", "pid": "all"}
            self.filter_mode = cycle.get(self.filter_mode, "all")
            self.filter_pid = None
            self.ev_scroll = 0
            self._set_status("filter=%s" % self.filter_mode, short=True)
            return
        if ch == "/":
            value = self._prompt("text filter: ")
            if value is not None:
                self.text_filter = value
                self.filter_pid = None
                self.ev_scroll = 0
                self._set_status(
                    "text filter=%r" % value if value else "text filter cleared",
                    short=True,
                )
            return
        if ch in ("c", "C"):
            self.events.clear()
            self.ev_scroll = 0
            self._set_status("event list cleared", short=True)
            return
        if ch == "e":
            self._export()
            return
        if ch == "v":
            self.view_mode = "files" if self.view_mode != "files" else "events"
            self._set_status("view=%s" % self.view_mode, short=True)
            return
        if ch == "n":
            self.view_mode = "net" if self.view_mode != "net" else "events"
            self._set_status("view=%s" % self.view_mode, short=True)
            return
        if ch == "a":
            self.show_nonfile = not self.show_nonfile
            self._set_status(
                "showing sockets/pipes" if self.show_nonfile else "showing regular files only",
                short=True,
            )
            return
        if ch in ("+", "="):
            self.interval = max(0.1, self.interval / 1.5)
            self.monitor.interval = self.interval
            self._next_poll = time.monotonic() + self.interval
            self._set_status("interval=%.2fs" % self.interval, short=True)
            return
        if ch in ("-", "_"):
            self.interval = min(30.0, self.interval * 1.5)
            self.monitor.interval = self.interval
            self._next_poll = time.monotonic() + self.interval
            self._set_status("interval=%.2fs" % self.interval, short=True)
            return
        if ch == "[":
            self.ev_scroll = min(self.ev_scroll + 10, max(0, len(self.events) - 1))
            self._set_status("scrolled back %d" % self.ev_scroll, short=True)
            return
        if ch == "]":
            self.ev_scroll = max(0, self.ev_scroll - 10)
            self._set_status(
                "live tail" if self.ev_scroll == 0 else "scrolled back %d" % self.ev_scroll,
                short=True,
            )
            return
        if ch == "?":
            self._help()
            return
        if ch == "redraw":
            self._dirty = True

    def _move_selection(self, delta: int) -> None:
        procs = self.monitor.process_list()
        if not procs:
            return
        index = self._proc_index or 0
        index = max(0, min(len(procs) - 1, index + delta))
        self._proc_index = index
        self.selected_pid = procs[index].pid
        self._dirty = True

    def _prompt(self, label: str) -> Optional[str]:
        width, height = self._size()
        chars: List[str] = []
        try:
            self._out.write("\x1b[?25h")
            while True:
                prompt = label + "".join(chars)
                self._out.write(
                    "\x1b[%d;1H%s%s" % (height, CLEAR_LINE, head_fit(prompt, width - 1))
                )
                self._out.flush()
                key = self._read_key(None)
                if key is None:
                    continue
                if key == "enter":
                    return "".join(chars)
                if key in ("esc", "ctrl-c"):
                    return None
                if key == "backspace":
                    if chars:
                        chars.pop()
                    continue
                if len(key) == 1 and 32 <= ord(key) < 127 and len(chars) < 120:
                    chars.append(key)
        finally:
            try:
                self._out.write("\x1b[?25l")
                self._out.flush()
            except OSError:
                pass
            self._dirty = True

    def _help(self) -> None:
        width, height = self._size()
        box_height = min(len(HELP_LINES) + 2, height - 2)
        box_width = min(max(len(line) for line in HELP_LINES) + 4, width - 2)
        top = max(0, (height - box_height) // 2)
        left = max(0, (width - box_width) // 2)
        lines = []
        lines.append(" " * left + "+" + "-" * (box_width - 2) + "+")
        for index in range(box_height - 2):
            text = HELP_LINES[index] if index < len(HELP_LINES) else ""
            text = head_fit(text, box_width - 4)
            lines.append(" " * left + "| " + text.ljust(box_width - 4) + " |")
        lines.append(" " * left + "+" + "-" * (box_width - 2) + "+")
        while len(lines) < height:
            lines.append("")
        self._write_screen(lines[:height])
        key = self._read_key(None)
        if key in ("ctrl-c", "q"):
            self.running = False
        self._dirty = True

    def _export(self) -> None:
        data = self.monitor.export()
        data["alerts"] = [e.to_dict() for e in self.events if e.kind == "alert"]
        data["violations"] = [e.to_dict() for e in self.events if e.kind == "violation"]
        data["database_events"] = [
            e.to_dict() for e in self.events if e.kind.startswith("db_")
        ]
        data["notes"] = self.notes
        filename = "proctrace-%d-%s.json" % (
            self.monitor.root_pid,
            time.strftime("%Y%m%d-%H%M%S"),
        )
        try:
            with open(filename, "w", encoding="utf-8", errors="backslashreplace") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
            self._set_status("exported %s" % os.path.abspath(filename), long=True)
        except (OSError, UnicodeError) as exc:
            self._set_status("export failed: %s" % exc, long=True)

    def _set_status(self, message: str, short: bool = False, long: bool = False) -> None:
        self._status = message
        self._status_until = 0 if long else time.time() + (3.0 if short else 6.0)
        self._dirty = True
