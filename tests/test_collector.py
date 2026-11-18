from proctrace.collector import _mode_from_flags, classify_raw


def test_classify_regular_file():
    info = classify_raw("/private/tmp/foo.txt")
    assert info.kind == "file"
    assert info.path == "/private/tmp/foo.txt"
    assert not info.deleted


def test_classify_deleted_file():
    info = classify_raw("/private/tmp/foo.txt (deleted)")
    assert info.kind == "file"
    assert info.path == "/private/tmp/foo.txt"
    assert info.deleted


def test_classify_pseudo_files():
    assert classify_raw("socket:[1234]").kind == "socket"
    assert classify_raw("pipe:[1234]").kind == "pipe"
    assert classify_raw("anon_inode:[eventpoll]").kind == "anon"
    assert classify_raw("anon_inode:[pidfd]").kind == "anon"


def test_mode_from_flags():
    assert _mode_from_flags(0) == "r"
    assert _mode_from_flags(1) == "w"
    assert _mode_from_flags(2) == "rw"


def test_linux_procfs_fake_tree(tmp_path):
    from proctrace.collector import LinuxProcCollector

    root = tmp_path / "proc"
    (root / "self" / "fd").mkdir(parents=True)
    pid = root / "123"
    (pid / "fd").mkdir(parents=True)
    (pid / "fdinfo").mkdir()
    import os

    os.symlink("/tmp/a.txt", str(pid / "fd" / "3"))
    os.symlink("socket:[99]", str(pid / "fd" / "4"))
    os.symlink("anon_inode:[pidfd]", str(pid / "fd" / "5"))
    (pid / "fdinfo" / "3").write_text("pos:\t0\nflags:\t0100002\n", encoding="utf-8")
    (pid / "fdinfo" / "5").write_text("pos:\t0\nflags:\t02000000\nPid:\t777\n", encoding="utf-8")
    (pid / "status").write_text("Name:\tpython\nTracerPid:\t42\n", encoding="utf-8")

    collector = LinuxProcCollector(str(root))
    fds = collector.list_fds(123)
    assert set(fds) == {3, 4, 5}
    assert fds[3].kind == "file"
    assert fds[4].kind == "socket"

    described = collector.describe(123, fds[3])
    assert described.mode == "rw"
    pidfd = collector.describe(123, fds[5])
    assert pidfd.target_pid == 777
    assert pidfd.detail == "pidfd"
    assert collector.ptrace_tracer(123) == 42
