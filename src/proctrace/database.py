"""Local database-file classification.

SQLite/DuckDB files are still files; kernel events can tell us they were
opened/read/written, but not which SQL statement ran.  Statement-level
monitoring requires the database's own audit/general log or a proxy.
"""

from __future__ import annotations

from typing import Optional, Sequence

DEFAULT_SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")
DEFAULT_LOCAL_DB_SUFFIXES = (
    ".db",
    ".sqlite",
    ".sqlite3",
    ".duckdb",
    ".mdb",
    ".accdb",
)


def database_service(path: str, suffixes: Optional[Sequence[str]] = None) -> str:
    if not path:
        return ""
    lower = path.lower()
    exts = tuple(suffixes) if suffixes else DEFAULT_LOCAL_DB_SUFFIXES
    for suffix in exts:
        suffix = suffix.lower()
        if lower.endswith(suffix):
            if suffix == ".duckdb":
                return "duckdb"
            if suffix in (".mdb", ".accdb"):
                return "access"
            return "sqlite"
    # SQLite sidecar files are part of the same database.
    for suffix in (".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm"):
        if lower.endswith(suffix):
            return "sqlite"
    return ""


def database_operation(mode: str) -> str:
    mode = (mode or "").lower()
    if "rw" in mode or "+" in mode:
        return "read_write"
    if "w" in mode:
        return "write"
    if "r" in mode:
        return "read"
    return "unknown"


def db_event_kind(service: str) -> str:
    return "db_file" if service else ""
