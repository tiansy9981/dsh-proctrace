"""Unprivileged network-connection monitoring and database endpoint classification.

Connections are polled through libproc (macOS) or /proc (Linux) using psutil.
Byte counts and SQL statements are intentionally not guessed here.
"""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

import psutil

from .config import NetworkConfig

DEFAULT_DB_PORTS: Dict[int, str] = {
    1433: "mssql",
    1521: "oracle",
    2379: "etcd",
    2380: "etcd",
    3306: "mysql",
    3307: "mysql",
    5432: "postgresql",
    5433: "postgresql",
    6379: "redis",
    6380: "redis",
    8086: "influxdb",
    8123: "clickhouse",
    9000: "clickhouse",
    9042: "cassandra",
    9200: "elasticsearch",
    9300: "elasticsearch",
    26257: "cockroachdb",
    27017: "mongodb",
    27018: "mongodb",
}

UNIX_DB_PATTERNS = (
    (re.compile(r"\.s\.PGSQL\.\d+$"), "postgresql"),
    (re.compile(r"mysqld?\.sock$"), "mysql"),
    (re.compile(r"redis.*\.sock$"), "redis"),
    (re.compile(r"mongodb.*\.sock$", re.I), "mongodb"),
)

_KIND_NAMES = {
    socket.SOCK_STREAM: "tcp",
    socket.SOCK_DGRAM: "udp",
    socket.SOCK_SEQPACKET: "seqpacket",
}


@dataclass(frozen=True)
class Connection:
    pid: int
    fd: int
    family: str
    proto: str
    local: str
    remote: str
    status: str
    service: str = ""

    def key(self) -> Tuple:
        return (
            self.pid,
            self.fd,
            self.family,
            self.proto,
            self.local,
            self.remote,
        )

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "pid": self.pid,
            "fd": self.fd,
            "family": self.family,
            "proto": self.proto,
            "local": self.local,
            "remote": self.remote,
            "status": self.status,
        }
        if self.service:
            data["service"] = self.service
        return data

    def display(self) -> str:
        target = self.remote or "-"
        service = " %s" % self.service if self.service else ""
        return "%s %s -> %s%s" % (self.proto, self.local or "-", target, service)


@dataclass
class NetworkEvent:
    kind: str
    conn: Connection
    old_status: str = ""
    initial: bool = False


def _addr_parts(value) -> Tuple[str, int]:
    if value is None:
        return ("", 0)
    if isinstance(value, str):
        return (value, 0)
    if isinstance(value, (tuple, list)):
        if len(value) >= 2:
            return (str(value[0] or ""), int(value[1] or 0))
        if value:
            return (str(value[0] or ""), 0)
        return ("", 0)
    ip = getattr(value, "ip", None)
    port = getattr(value, "port", None)
    if ip is None and port is None:
        return (str(value), 0)
    return (str(ip or ""), int(port or 0))


def _family_name(family) -> str:
    try:
        value = int(family)
    except (TypeError, ValueError):
        return str(family)
    if value == int(socket.AF_INET):
        return "inet"
    if value == int(socket.AF_INET6):
        return "inet6"
    if value == int(socket.AF_UNIX):
        return "unix"
    return str(value)


def _unix_service(path: str) -> str:
    for pattern, name in UNIX_DB_PATTERNS:
        if pattern.search(path):
            return name
    return ""


class NetworkMonitor:
    def __init__(self, config: NetworkConfig, provider=None) -> None:
        self.enabled = bool(config.enabled)
        self.include_unix = bool(config.include_unix)
        self.ignore_ports: Set[int] = set(config.ignore_ports)
        self.db_ports: Dict[int, str] = dict(DEFAULT_DB_PORTS)
        self.db_ports.update(config.db_ports)
        self._provider = provider or self._psutil_connections
        self._state: Dict[Tuple, Connection] = {}
        self._recent: Dict[Tuple, Tuple[Connection, float]] = {}
        self._initial_done = False
        self.last_errors: List[str] = []
        self._warned: Set[str] = set()

    # ------------------------------------------------------------------ public
    def poll(
        self, pids: Sequence[int], show_initial: bool = False
    ) -> Tuple[List[NetworkEvent], List[str]]:
        events: List[NetworkEvent] = []
        errors: List[str] = []
        current: Dict[Tuple, Connection] = {}
        if not self.enabled:
            self.last_errors = []
            return events, errors

        for pid in pids:
            try:
                connections = self._provider(pid)
            except psutil.NoSuchProcess:
                connections = []
            except (psutil.AccessDenied, psutil.ZombieProcess) as exc:
                message = "pid %d network: %s" % (pid, exc)
                if message not in self._warned:
                    self._warned.add(message)
                    errors.append(message)
                # Keep the old state for this pid to avoid false "closed" events.
                for key, conn in self._state.items():
                    if key[0] == pid:
                        current[key] = conn
                continue
            except OSError as exc:
                errors.append("pid %d network: %s" % (pid, exc))
                continue
            for conn in connections:
                if self._ignored(conn):
                    continue
                key = conn.key()
                current[key] = conn
                old = self._state.get(key)
                if old is None:
                    kind = "db_connect" if conn.service else "net_open"
                    events.append(
                        NetworkEvent(
                            kind,
                            conn,
                            initial=not self._initial_done,
                        )
                    )
                elif old.status != conn.status:
                    kind = "db_change" if conn.service else "net_change"
                    events.append(NetworkEvent(kind, conn, old_status=old.status))

        for key, old in self._state.items():
            if key not in current:
                kind = "db_close" if old.service else "net_close"
                events.append(NetworkEvent(kind, old))

        now = time.time()
        for key, conn in current.items():
            self._recent[key] = (conn, now)
        for key, (conn, seen) in list(self._recent.items()):
            if now - seen > 120.0:
                self._recent.pop(key, None)
        self._state = current
        self._initial_done = True
        self.last_errors = errors
        return events, errors

    def connections_for(self, pid: int) -> List[Connection]:
        return sorted(
            (conn for key, conn in self._state.items() if key[0] == pid),
            key=lambda c: (c.family, c.proto, c.remote, c.local, c.fd),
        )

    def all_connections(self) -> List[Connection]:
        return sorted(
            self._state.values(),
            key=lambda c: (c.pid, c.family, c.proto, c.remote, c.local, c.fd),
        )

    def find_client_pid(
        self, host: str, port: int = 0, family: str = ""
    ) -> Optional[int]:
        """Best-effort map of a DB log client endpoint to a monitored PID.

        PostgreSQL's log_line_prefix %r gives client host(port); matching the
        client's local endpoint is reliable.  Host-only logs are accepted only
        when exactly one monitored DB connection matches.
        """
        if not self.enabled or not host:
            return None
        host = host.strip("[]")
        matches = []
        candidates = list(self._state.values())
        candidates.extend(conn for conn, _ in self._recent.values())
        for conn in candidates:
            remote_port = self._port(conn.remote)
            if not conn.service and remote_port not in self.db_ports:
                continue
            local_host = conn.local.rsplit(":", 1)[0].strip("[]") if ":" in conn.local else conn.local.strip("[]")
            if local_host != host and conn.local != host:
                continue
            if port and self._port(conn.local) != port:
                continue
            matches.append(conn.pid)
        unique = sorted(set(matches))
        return unique[0] if len(unique) == 1 else None

    def clear_pid(self, pid: int) -> None:
        for key in [k for k in self._state if k[0] == pid]:
            self._state.pop(key, None)
        for key in [k for k in self._recent if k[0] == pid]:
            self._recent.pop(key, None)

    # ---------------------------------------------------------------- internal
    def _ignored(self, conn: Connection) -> bool:
        if not self.include_unix and conn.family == "unix":
            return True
        for port in self.ignore_ports:
            if port and (port == self._port(conn.local) or port == self._port(conn.remote)):
                return True
        return False

    @staticmethod
    def _port(value: str) -> int:
        if not value or ":" not in value:
            return 0
        try:
            return int(value.rsplit(":", 1)[1])
        except ValueError:
            return 0

    def _service_for(self, family: str, local: str, remote: str) -> str:
        if family == "unix":
            return _unix_service(remote) or _unix_service(local)
        for value in (remote, local):
            port = self._port(value)
            if port in self.db_ports:
                return self.db_ports[port]
        return ""

    def _psutil_connections(self, pid: int) -> List[Connection]:
        proc = psutil.Process(pid)
        try:
            raw = proc.net_connections(kind="all")
        except AttributeError:  # psutil < 5.9 fallback
            raw = proc.connections(kind="all")
        result: List[Connection] = []
        for item in raw:
            family = _family_name(getattr(item, "family", ""))
            if family not in ("inet", "inet6", "unix"):
                continue
            if family == "inet" or family == "inet6":
                lhost, lport = _addr_parts(getattr(item, "laddr", None))
                rhost, rport = _addr_parts(getattr(item, "raddr", None))
                local = "%s:%d" % (lhost, lport) if lhost else ""
                remote = "%s:%d" % (rhost, rport) if rhost else ""
                proto = _KIND_NAMES.get(getattr(item, "type", None), "inet")
            else:
                local, _ = _addr_parts(getattr(item, "laddr", None))
                remote, _ = _addr_parts(getattr(item, "raddr", None))
                if not local and not remote:
                    continue
                proto = "unix"
            service = self._service_for(family, local, remote)
            result.append(
                Connection(
                    pid=pid,
                    fd=int(getattr(item, "fd", -1) or -1),
                    family=family,
                    proto=proto,
                    local=local,
                    remote=remote,
                    status=str(getattr(item, "status", "") or ""),
                    service=service,
                )
            )
        return result
