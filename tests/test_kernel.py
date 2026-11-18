import json
import os
import struct
import sys

import pytest

from proctrace.kernel import (
    FAN_ACCESS,
    FAN_CLOSE_NOWRITE,
    FAN_CLOSE_WRITE,
    FAN_OPEN,
    LinuxFanotifySource,
    MacEsloggerSource,
    fanotify_kinds,
)


def test_eslogger_open_parse():
    line = json.dumps(
        {
            "event": {"open": {"file": {"path": "/tmp/secret.txt"}, "fflag": 2}},
            "process": {"audit_token": {"pid": 42}},
        }
    )
    event = MacEsloggerSource.parse_line(line)
    assert event is not None
    assert event.pid == 42
    assert event.kind == "open"
    assert event.path == "/tmp/secret.txt"
    assert event.mode == "rw"


def test_eslogger_close_and_write_parse():
    close = json.dumps(
        {
            "event": {"close": {"target": {"path": "/tmp/a"}}},
            "process": {"pid": 7},
        }
    )
    assert MacEsloggerSource.parse_line(close).kind == "close"
    write = json.dumps(
        {
            "event": {"write": {"target": {"path": "/tmp/a"}}},
            "process": {"audit_token": {"pid": 7}},
        }
    )
    event = MacEsloggerSource.parse_line(write)
    assert event.kind == "write"
    assert event.mode == "w"


def test_eslogger_ignores_garbage():
    assert MacEsloggerSource.parse_line("not json") is None
    assert MacEsloggerSource.parse_line('{"event": {}}') is None


def test_fanotify_mask_mapping():
    assert fanotify_kinds(FAN_OPEN) == ["open"]
    assert fanotify_kinds(FAN_ACCESS) == ["read"]
    assert fanotify_kinds(FAN_CLOSE_WRITE) == ["write", "close"]
    assert fanotify_kinds(FAN_CLOSE_NOWRITE) == ["close"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux fanotify only")
def test_fanotify_decode_synthetic(tmp_path):
    path = tmp_path / "x.txt"
    path.write_text("x")
    fd = os.open(path, os.O_RDONLY)
    data = struct.pack("=IBBHQii", 24, 1, 0, 24, FAN_OPEN, fd, 123)
    decoded = LinuxFanotifySource.decode_buffer(data)
    assert decoded == [("open", 123, str(path))]
