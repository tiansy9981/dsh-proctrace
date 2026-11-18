import json
import os
import subprocess
import sys
import time

import pytest

from proctrace.config import DbAuditConfig, DbAuditSourceConfig
from proctrace.db_audit import (
    DbAuditSource,
    assess_sql,
    find_sqlite_shim,
    parse_postgres_line,
    redact_sql,
)


def test_redact_sql_literals():
    sql = "SELECT * FROM users WHERE name='bob' AND id=42 AND token='a''b' -- comment"
    assert redact_sql(sql) == "SELECT * FROM users WHERE name=? AND id=? AND token=?"
    assert redact_sql("SELECT $$secret$$") == "SELECT ?"
    assert redact_sql("SELECT col1 FROM t") == "SELECT col1 FROM t"


def test_assess_sql():
    assert assess_sql("DROP TABLE users", [])[1] == "high"
    assert assess_sql("DELETE FROM users", [])[1] == "high"
    assert assess_sql("DELETE FROM users WHERE id=1", [])[1] == "medium"
    assert assess_sql("SELECT * FROM users", ["users"])[2] == "sensitive_table:users"
    assert assess_sql("COPY users TO '/tmp/x'", [])[2] == "bulk_export"


def test_parse_postgres_line():
    line = (
        "2026-11-17 20:00:00.123 CST [1234] app@prod 10.0.0.5(54321) "
        "LOG:  statement: SELECT * FROM users WHERE id=42"
    )
    event = parse_postgres_line(line)
    assert event is not None
    assert event.system == "postgresql"
    assert event.database == "prod"
    assert event.client_host == "10.0.0.5"
    assert event.client_port == 54321
    assert event.sql == "SELECT * FROM users WHERE id=?"


def test_file_tail_and_mysql(tmp_path):
    pg = tmp_path / "pg.log"
    my = tmp_path / "mysql.log"
    pg.write_text("", encoding="utf-8")
    my.write_text("", encoding="utf-8")
    cfg = DbAuditConfig(
        enabled=True,
        sources=[
            DbAuditSourceConfig("postgresql", str(pg)),
            DbAuditSourceConfig("mysql", str(my)),
        ],
    )
    source = DbAuditSource(cfg)
    with pg.open("a", encoding="utf-8") as handle:
        handle.write(
            "2026-11-17 20:00:00.123 CST [1] app@db 10.0.0.5(1234) "
            "LOG:  statement: DROP TABLE users\n"
        )
    with my.open("a", encoding="utf-8") as handle:
        handle.write("2026-11-17T20:00:00.123456+08:00 77 Connect app@10.1.1.2 on db\n")
        handle.write("2026-11-17T20:00:00.200000+08:00 77 Query SELECT * FROM users\n")
    events, errors = source.poll()
    source.close()
    assert not errors
    assert [e.system for e in events] == ["postgresql", "mysql"]
    assert events[0].risk == "high"
    assert events[1].operation == "SELECT"


@pytest.mark.skipif(not (sys.platform == "darwin" or sys.platform.startswith("linux")),
                    reason="SQLite shim platform")
def test_sqlite_shim_end_to_end(tmp_path):
    shim = find_sqlite_shim()
    if not shim:
        pytest.skip("SQLite shim not built; run scripts/build_shim.sh")
    sock = "/tmp/proctrace-sqlite-test-%d.sock" % os.getpid()
    source = DbAuditSource(
        DbAuditConfig(
            enabled=True,
            sources=[DbAuditSourceConfig("sqlite", sock)],
        )
    )
    env = dict(os.environ)
    env.update(source.shim_env())
    code = (
        "import sqlite3\n"
        "c=sqlite3.connect(%r)\n"
        "c.execute('create table t(x)')\n"
        "c.execute('insert into t values (1)')\n"
        "c.execute('select * from t').fetchall()\n"
        "c.close()\n"
    ) % str(tmp_path / "test.db")
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        time.sleep(0.2)
        events, errors = source.poll()
        assert not errors
        assert events
        assert any(e.system == "sqlite" and "create table" in e.sql.lower() for e in events)
        assert any(e.agent_pid for e in events)
    finally:
        source.close()
