from proctrace.model import Event, FdInfo
from proctrace.render import event_line, human_snapshot, is_visible_event


def test_event_line_open_and_alert():
    event = Event(ts=1.0, kind="open", pid=10, name="python", fd=3,
                  path="/tmp/a b.txt", mode="r", file_kind="file")
    line = event_line(event, show_nonfile=False)
    assert "OPEN" in line
    assert "/tmp/a b.txt" in line

    alert = Event(ts=1.0, kind="alert", pid=10, name="python", fd=9,
                  path="/proc/20/mem", victim_pid=20, victim_name="secret",
                  via="procfs")
    line = event_line(alert, show_nonfile=False)
    assert "ALERT" in line
    assert "secret" in line
    assert "procfs" in line


def test_nonfile_filter():
    event = Event(ts=1.0, kind="open", pid=10, name="python", fd=3,
                  path="socket:[1]", file_kind="socket")
    assert not is_visible_event(event, show_nonfile=False)
    assert is_visible_event(event, show_nonfile=True)


def test_snapshot_render():
    data = {
        "generated_at": 0,
        "backend": "fake",
        "target_pid": 10,
        "stats": {"processes": 1, "fds": 1, "alerts": 0},
        "processes": [
            {
                "pid": 10,
                "ppid": 1,
                "name": "python",
                "depth": 0,
                "protected": False,
                "excluded": False,
                "fd_count": 1,
                "files": [FdInfo(3, "/tmp/x.txt", "file").to_dict()],
            }
        ],
        "alerts": [],
    }
    text = human_snapshot(data)
    assert "python" in text
    assert "/tmp/x.txt" in text
