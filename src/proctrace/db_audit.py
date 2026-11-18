"""Database audit-log ingestion and SQL normalization.

PostgreSQL/MySQL logs are tailed from disk.  SQLite has no server audit log;
the optional shim (see shim/proctrace_sqlite.c) sends prepared statements over
a Unix datagram socket.  SQL is redacted before it reaches any log sink.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import socket
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .config import DbAuditConfig, DbAuditSourceConfig

SQL_COMMANDS = {
    "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "UPSERT",
    "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "COPY",
    "CALL", "EXEC", "EXECUTE", "WITH", "SHOW", "SET", "USE", "BEGIN",
    "COMMIT", "ROLLBACK", "VACUUM", "ANALYZE", "REINDEX", "DO", "LISTEN",
    "NOTIFY", "UNLISTEN", "PREPARE", "DEALLOCATE", "DECLARE", "FETCH",
}
DDL_COMMANDS = {
    "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "REINDEX",
    "VACUUM",
}
WRITE_COMMANDS = {
    "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "UPSERT", "COPY",
    "CALL", "EXEC", "EXECUTE", "DO",
}

_PG_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_MYSQL_TS = _PG_TS
_PG_PID = re.compile(r"\[(\d+)\]")
_PG_USER_DB = re.compile(r"\]\s+([^@\s]+)@([^\s]+)")
_PG_CLIENT = re.compile(
    r"([0-9a-fA-F:.]+)\((\d+)\)|((?:\d{1,3}\.){3}\d{1,3}):(\d+)"
)
_MYSQL_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(\d+)\s+(\w+)\s*(.*)$"
)
_DOLLAR_QUOTE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class DbQueryEvent:
    ts: float
    system: str
    sql: str
    operation: str = ""
    risk: str = "low"
    reason: str = ""
    database: str = ""
    db_user: str = ""
    client_host: str = ""
    client_port: int = 0
    backend_pid: str = ""
    thread_id: str = ""
    agent_pid: Optional[int] = None

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "ts": round(self.ts, 6),
            "system": self.system,
            "operation": self.operation,
            "risk": self.risk,
            "reason": self.reason,
            "sql": self.sql,
        }
        for key in ("database", "db_user", "client_host", "backend_pid", "thread_id"):
            value = getattr(self, key)
            if value:
                data[key] = value
        if self.client_port:
            data["client_port"] = self.client_port
        if self.agent_pid is not None:
            data["agent_pid"] = self.agent_pid
        return data


def redact_sql(sql: str, max_len: int = 12000) -> str:
    """Replace literals while keeping SQL structure for detection/logging."""
    if not sql:
        return ""
    sql = sql.strip()
    out: List[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            j = sql.find("\n", i + 2)
            i = n if j < 0 else j + 1
            out.append(" ")
            continue
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        if ch == "'":
            i += 1
            while i < n:
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                if sql[i] == "\\":
                    i += 2
                else:
                    i += 1
            out.append("?")
            continue
        if ch == "$":
            match = _DOLLAR_QUOTE.match(sql, i)
            if match:
                delimiter = match.group(0)
                end = sql.find(delimiter, match.end())
                if end >= 0:
                    i = end + len(delimiter)
                    out.append("?")
                    continue
        if ch.isdigit() and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] in "_$")):
            i += 1
            while i < n and (sql[i].isalnum() or sql[i] in ".xX_+-"):
                i += 1
            out.append("?")
            continue
        out.append(ch)
        i += 1
    result = re.sub(r"\s+", " ", "".join(out)).strip()
    if len(result) > max_len:
        result = result[: max_len - 1] + "\u2026"
    return result


def _first_operation(sql: str) -> str:
    match = re.match(r"\s*([A-Za-z]+)", sql)
    return match.group(1).upper() if match else ""


def assess_sql(sql: str, sensitive_tables: Sequence[str]) -> Tuple[str, str, str]:
    """Return (operation, risk, reason) for a redacted SQL statement."""
    operation = _first_operation(sql)
    lower = sql.lower()
    padded = " " + lower + " "
    reason = ""
    risk = "low"
    if operation in DDL_COMMANDS:
        risk, reason = "high", "destructive_ddl"
    elif "into outfile" in lower or "into dumpfile" in lower:
        risk, reason = "high", "file_export"
    elif "load_file(" in lower or "pg_read_file(" in lower or "lo_import(" in lower:
        risk, reason = "high", "file_read_function"
    elif "xp_cmdshell" in lower:
        risk, reason = "high", "command_execution"
    elif operation == "COPY":
        if " to " in padded:
            risk, reason = "high", "bulk_export"
        else:
            risk, reason = "medium", "bulk_load"
    elif operation in ("DELETE", "UPDATE") and " where " not in padded:
        risk, reason = "high", "mass_%s" % operation.lower()
    elif operation in WRITE_COMMANDS:
        risk, reason = "medium", "write_operation"
    elif operation == "SELECT":
        tokens = {token.lower() for token in _IDENT.findall(sql)}
        hits = [table for table in sensitive_tables if table.lower() in tokens]
        if hits:
            risk, reason = "medium", "sensitive_table:%s" % ",".join(hits[:3])
        else:
            risk, reason = "low", "read"
    else:
        risk, reason = "low", "other"
    return operation, risk, reason


def parse_timestamp(line: str) -> float:
    pattern = _PG_TS.match(line) or _MYSQL_TS.match(line)
    if not pattern:
        return time.time()
    text = pattern.group(1).replace(" ", "T", 1).replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", text):
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]
    try:
        return _dt.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return time.time()


def _pg_sql(line: str) -> str:
    # log_statement / log_min_duration_statement / execute
    match = re.search(
        r"(?:LOG|ERROR|FATAL):\s+.*?(?:statement|execute [^:]+):\s*(.*)$",
        line,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    if "AUDIT:" in line:
        # pgaudit: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT ...
        # The statement is after the last ",<command> " field.
        matches = list(
            re.finditer(
                r",\s*(SELECT|INSERT|UPDATE|DELETE|COPY|ALTER|DROP|CREATE|GRANT|"
                r"REVOKE|TRUNCATE|CALL|EXECUTE|WITH)\b",
                line,
                re.IGNORECASE,
            )
        )
        if matches:
            return line[matches[-1].start() + 1 :].strip()
    return ""


def parse_postgres_line(line: str) -> Optional[DbQueryEvent]:
    sql = _pg_sql(line)
    if not sql:
        return None
    pid_match = _PG_PID.search(line)
    user_db = _PG_USER_DB.search(line)
    client = _PG_CLIENT.search(line.split("LOG:", 1)[0])
    client_host = ""
    client_port = 0
    if client:
        client_host = client.group(1) or client.group(3) or ""
        client_port = int(client.group(2) or client.group(4) or 0)
    database = user_db.group(2) if user_db else ""
    user = user_db.group(1) if user_db else ""
    op, risk, reason = assess_sql(redact_sql(sql), [])
    return DbQueryEvent(
        ts=parse_timestamp(line),
        system="postgresql",
        sql=redact_sql(sql),
        operation=op,
        risk=risk,
        reason=reason,
        database=database,
        db_user=user,
        client_host=client_host,
        client_port=client_port,
        backend_pid=pid_match.group(1) if pid_match else "",
    )


class DbAuditSource:
    def __init__(self, config: DbAuditConfig) -> None:
        self.config = config
        self.enabled = bool(config.enabled and config.sources)
        self._tails: List[Tuple[DbAuditSourceConfig, _FileTail]] = []
        self._sqlite_sock: Optional[socket.socket] = None
        self._sqlite_path = ""
        self._threads: Dict[str, Dict[str, str]] = {}
        self._errors: List[str] = []
        self._warned: set = set()
        self._setup()

    def _setup(self) -> None:
        for source in self.config.sources:
            if source.system == "sqlite":
                self._setup_sqlite(source.path)
            else:
                self._tails.append((source, _FileTail(source.path, self.config.from_start)))

    def _setup_sqlite(self, path: str) -> None:
        if not path:
            self._error("SQLite socket path 为空")
            return
        try:
            if os.path.exists(path):
                mode = stat.S_IMODE(os.stat(path).st_mode)
                if not stat.S_ISSOCK(os.stat(path).st_mode):
                    self._error("SQLite socket 路径已存在且不是 socket: %s" % path)
                    return
                os.unlink(path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            except OSError:
                pass
            sock.bind(path)
            os.chmod(path, 0o600)
            sock.setblocking(False)
            self._sqlite_sock = sock
            self._sqlite_path = path
        except OSError as exc:
            self._error("创建 SQLite socket 失败 %s: %s" % (path, exc))

    def _error(self, message: str) -> None:
        if message not in self._warned:
            self._warned.add(message)
            self._errors.append(message)

    @property
    def sqlite_path(self) -> str:
        return self._sqlite_path

    def ignore_paths(self) -> List[str]:
        paths = []
        if self._sqlite_path:
            paths.append(self._sqlite_path)
        library = find_sqlite_shim()
        if library:
            paths.append(library)
        return paths

    def shim_env(self) -> Dict[str, str]:
        if not self._sqlite_path:
            return {}
        library = find_sqlite_shim()
        if not library:
            return {"PROCTRACE_SQLITE_SOCK": self._sqlite_path}
        env = {"PROCTRACE_SQLITE_SOCK": self._sqlite_path}
        if sys_platform() == "darwin":
            env["DYLD_INSERT_LIBRARIES"] = library
        else:
            env["LD_PRELOAD"] = library
        return env

    def poll(self) -> Tuple[List[DbQueryEvent], List[str]]:
        events: List[DbQueryEvent] = []
        errors: List[str] = []
        if not self.enabled:
            return events, errors
        for source, tail in self._tails:
            lines = tail.read_lines()
            if tail.error:
                errors.append(tail.error)
            for line in lines:
                try:
                    if source.system == "postgresql":
                        event = parse_postgres_line(line)
                    else:
                        event = self._parse_mysql(line)
                except Exception:
                    event = None
                if event is not None:
                    event.operation, event.risk, event.reason = assess_sql(
                        event.sql, self.config.sensitive_tables
                    )
                    events.append(event)
        if self._sqlite_sock is not None:
            while True:
                try:
                    data, _ = self._sqlite_sock.recvfrom(65535)
                except BlockingIOError:
                    break
                except OSError:
                    break
                try:
                    obj = json.loads(data.decode("utf-8", "replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                sql = redact_sql(str(obj.get("sql", "")))
                if not sql:
                    continue
                operation, risk, reason = assess_sql(sql, self.config.sensitive_tables)
                try:
                    pid = int(obj.get("pid")) if obj.get("pid") is not None else None
                except (TypeError, ValueError):
                    pid = None
                events.append(
                    DbQueryEvent(
                        ts=float(obj.get("ts") or time.time()),
                        system="sqlite",
                        sql=sql,
                        operation=operation,
                        risk=risk,
                        reason=reason,
                        database=str(obj.get("db", "") or ""),
                        agent_pid=pid,
                    )
                )
        errors.extend(self._errors)
        self._errors = []
        return events, errors

    def _parse_mysql(self, line: str) -> Optional[DbQueryEvent]:
        match = _MYSQL_LINE.match(line)
        if not match:
            return None
        ts, thread, command, rest = match.groups()
        command = command.lower()
        context = self._threads.setdefault(str(thread), {})
        if command == "connect":
            user = ""
            host = ""
            database = ""
            cm = re.match(r"([^@\s]+)@([^\s]+)(?:\s+on\s+(\S+))?", rest)
            if cm:
                user, host, database = cm.group(1), cm.group(2), cm.group(3) or ""
            context.update({"user": user, "host": host, "database": database})
            return None
        if command == "quit":
            self._threads.pop(str(thread), None)
            return None
        if command == "init db":
            context["database"] = rest.strip()
            return None
        if command not in ("query", "execute"):
            return None
        sql = rest.strip()
        if not sql:
            return None
        redacted = redact_sql(sql)
        operation, risk, reason = assess_sql(redacted, self.config.sensitive_tables)
        host = context.get("host", "")
        client_host = host
        client_port = 0
        hm = re.match(r"([^:]+):(\d+)$", host)
        if hm:
            client_host, client_port = hm.group(1), int(hm.group(2))
        return DbQueryEvent(
            ts=parse_timestamp(line),
            system="mysql",
            sql=redacted,
            operation=operation,
            risk=risk,
            reason=reason,
            database=context.get("database", ""),
            db_user=context.get("user", ""),
            client_host=client_host,
            client_port=client_port,
            thread_id=str(thread),
        )

    def close(self) -> None:
        if self._sqlite_sock is not None:
            try:
                self._sqlite_sock.close()
            except OSError:
                pass
            self._sqlite_sock = None
        if self._sqlite_path:
            try:
                os.unlink(self._sqlite_path)
            except OSError:
                pass
            self._sqlite_path = ""


class _FileTail:
    def __init__(self, path: str, from_start: bool = False) -> None:
        self.path = path
        self.from_start = from_start
        self._offset = 0
        self._inode = None
        self._buffer = ""
        self._missing_warned = False
        self.error = ""
        self._open(initial=True)

    def _open(self, initial: bool = False) -> None:
        try:
            st = os.stat(self.path)
        except OSError as exc:
            self._inode = None
            self.error = "无法读取审计日志 %s: %s" % (self.path, exc)
            return
        self._inode = (st.st_dev, st.st_ino)
        if initial and not self.from_start:
            self._offset = st.st_size
        else:
            self._offset = 0
        self._buffer = ""

    def read_lines(self) -> List[str]:
        try:
            st = os.stat(self.path)
        except OSError as exc:
            self.error = "无法读取审计日志 %s: %s" % (self.path, exc)
            return []
        self.error = ""
        inode = (st.st_dev, st.st_ino)
        if inode != self._inode or st.st_size < self._offset:
            self._open(initial=False)
        if st.st_size == self._offset:
            return []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._offset)
                chunk = handle.read(1024 * 1024)
                self._offset = handle.tell()
        except OSError:
            return []
        data = self._buffer + chunk
        lines = data.split("\n")
        self._buffer = lines.pop() if lines else ""
        return [line for line in lines if line.strip()]


def sys_platform() -> str:
    import sys

    return sys.platform


def find_sqlite_shim() -> str:
    override = os.environ.get("PROCTRACE_SQLITE_SHIM")
    if override and os.path.isfile(override):
        return override
    root = Path(__file__).resolve().parents[2]
    names = (
        "libproctrace_sqlite.dylib",
        "libproctrace_sqlite.so",
    )
    for directory in (root / "build", root / "shim"):
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return str(candidate)
    return ""
