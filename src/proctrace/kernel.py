"""Optional kernel-level file event sources.

macOS uses Apple's pre-entitled ``eslogger`` EndpointSecurity client.  Linux
uses fanotify.  Both require root; both are optional, experimental backends
because they cannot be exercised in the unprivileged test environment.
"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import select
import shutil
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence, Set, Tuple


class KernelUnavailable(Exception):
    pass


@dataclass(frozen=True)
class KernelFileEvent:
    ts: float
    pid: int
    kind: str  # open, read, write, close
    path: str
    mode: str = ""
    detail: str = ""


def _fflag_mode(fflag) -> str:
    try:
        if isinstance(fflag, str):
            flags = int(fflag, 0)
        else:
            flags = int(fflag)
    except (TypeError, ValueError):
        return ""
    access = flags & 0o3
    return {0: "r", 1: "w", 2: "rw"}.get(access, "")


def _find_path(value) -> str:
    """Find the first plausible path in an eslogger event subtree."""
    if isinstance(value, str):
        return value if value.startswith("/") else ""
    if isinstance(value, dict):
        direct = value.get("path")
        if isinstance(direct, str) and direct.startswith("/"):
            return direct
        for key in ("file", "target", "source", "destination", "executable"):
            child = value.get(key)
            found = _find_path(child)
            if found:
                return found
        for child in value.values():
            found = _find_path(child)
            if found:
                return found
    if isinstance(value, list):
        for child in value:
            found = _find_path(child)
            if found:
                return found
    return ""


class KernelSource:
    name = "none"

    def start(self) -> None:
        raise NotImplementedError

    def update_pids(self, pids: Set[int]) -> None:
        raise NotImplementedError

    def drain(self) -> List[KernelFileEvent]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    @property
    def last_error(self) -> str:
        return ""

    @property
    def healthy(self) -> bool:
        return False


class MacEsloggerSource(KernelSource):
    name = "macos-eslogger"

    def __init__(self, include_writes: bool = True) -> None:
        self.include_writes = include_writes
        self._proc: Optional[subprocess.Popen] = None
        self._queue: "queue.Queue[KernelFileEvent]" = queue.Queue(maxsize=100000)
        self._pids: Set[int] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._error = ""

    @staticmethod
    def available() -> Tuple[bool, str]:
        if sys.platform != "darwin":
            return False, "macOS only"
        if os.geteuid() != 0:
            return False, "需要 root：请用 sudo 运行，或给终端 Full Disk Access 后 sudo"
        if not shutil.which("eslogger"):
            return False, "找不到 /usr/bin/eslogger（需要 macOS 13+）"
        return True, ""

    def start(self) -> None:
        ok, reason = self.available()
        if not ok:
            raise KernelUnavailable(reason)
        event_types = ["open", "close"]
        if self.include_writes:
            event_types.append("write")
        command = ["eslogger", "--format", "json"] + event_types
        try:
            self._proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                close_fds=True,
            )
        except OSError as exc:
            raise KernelUnavailable("启动 eslogger 失败: %s" % exc)
        self._threads = [
            threading.Thread(target=self._read_stdout, name="eslogger-out", daemon=True),
            threading.Thread(target=self._read_stderr, name="eslogger-err", daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _read_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            try:
                event = self.parse_line(line)
            except Exception:
                continue
            if event is None:
                continue
            with self._lock:
                allowed = event.pid in self._pids
            if not allowed:
                continue
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                self._error = "eslogger 事件队列已满，可能开始丢事件"
                break
        if not self._stop.is_set() and self._proc.poll() not in (None, 0):
            self._error = "eslogger 已退出（检查 root/Full Disk Access）"

    def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            text = line.strip()
            if text and not self._stop.is_set():
                self._error = text[-500:]

    @staticmethod
    def parse_line(line: str) -> Optional[KernelFileEvent]:
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        process = obj.get("process") or {}
        token = process.get("audit_token") or {}
        pid_value = token.get("pid") if isinstance(token, dict) else None
        if pid_value is None and isinstance(process, dict):
            pid_value = process.get("pid")
        try:
            pid = int(pid_value)
        except (TypeError, ValueError):
            return None
        if pid <= 0:
            return None
        event = obj.get("event")
        if not isinstance(event, dict):
            return None
        kind = next((k for k in ("open", "close", "write") if k in event), None)
        if kind is None:
            return None
        payload = event.get(kind) or {}
        path = _find_path(payload)
        if not path:
            return None
        mode = ""
        if kind == "open":
            mode = _fflag_mode(payload.get("fflag"))
        elif kind == "write":
            mode = "w"
        return KernelFileEvent(ts=time.time(), pid=pid, kind=kind, path=path, mode=mode)

    def update_pids(self, pids: Set[int]) -> None:
        with self._lock:
            self._pids = set(pids)

    def drain(self) -> List[KernelFileEvent]:
        result: List[KernelFileEvent] = []
        while True:
            try:
                result.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return result

    @property
    def last_error(self) -> str:
        return self._error

    @property
    def healthy(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def close(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
            except OSError:
                pass
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    self._proc.kill()
                except OSError:
                    pass
        for thread in self._threads:
            thread.join(timeout=1)
        self._threads = []


# Linux fanotify constants (linux/fanotify.h)
FAN_CLASS_NOTIF = 0x00000000
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020
FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010
FAN_ACCESS = 0x00000001
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_OPEN_EXEC = 0x00001000
AT_FDCWD = -100


def fanotify_kinds(mask: int) -> List[str]:
    kinds: List[str] = []
    if mask & FAN_OPEN:
        kinds.append("open")
    if mask & FAN_ACCESS:
        kinds.append("read")
    if mask & FAN_CLOSE_WRITE:
        kinds.append("write")
    if mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE):
        kinds.append("close")
    return kinds


class LinuxFanotifySource(KernelSource):
    name = "linux-fanotify"

    def __init__(self, mark_paths: Sequence[str], include_writes: bool = True) -> None:
        self.mark_paths = list(mark_paths) or ["/"]
        self.include_writes = include_writes
        self._fd = -1
        self._queue: "queue.Queue[KernelFileEvent]" = queue.Queue(maxsize=100000)
        self._pids: Set[int] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error = ""

    @staticmethod
    def available() -> Tuple[bool, str]:
        if not sys.platform.startswith("linux"):
            return False, "Linux only"
        if os.geteuid() != 0:
            return False, "需要 root：请用 sudo 运行"
        try:
            libc = ctypes.CDLL(None, use_errno=True)
        except OSError as exc:
            return False, "加载 libc 失败: %s" % exc
        if not hasattr(libc, "fanotify_init") or not hasattr(libc, "fanotify_mark"):
            return False, "内核/libc 不支持 fanotify"
        return True, ""

    def start(self) -> None:
        ok, reason = self.available()
        if not ok:
            raise KernelUnavailable(reason)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        libc.fanotify_init.restype = ctypes.c_int
        libc.fanotify_mark.argtypes = [
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_ulonglong,
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        libc.fanotify_mark.restype = ctypes.c_int
        flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        flags |= FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
        fd = libc.fanotify_init(flags, os.O_RDONLY)
        if fd < 0:
            err = ctypes.get_errno()
            raise KernelUnavailable("fanotify_init 失败: %s" % os.strerror(err))
        self._fd = fd
        mask = FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE | FAN_OPEN_EXEC
        if self.include_writes:
            mask |= FAN_CLOSE_WRITE
        marked = 0
        for path in self.mark_paths:
            if not os.path.isdir(path):
                self._error = "mark path 不是目录: %s" % path
                continue
            rc = libc.fanotify_mark(
                fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                ctypes.c_ulonglong(mask),
                AT_FDCWD,
                path.encode(),
            )
            if rc < 0:
                err = ctypes.get_errno()
                self._error = "fanotify_mark(%s) 失败: %s" % (path, os.strerror(err))
            else:
                marked += 1
        if not marked:
            error = self._error or "没有成功标记任何路径"
            try:
                os.close(fd)
            except OSError:
                pass
            self._fd = -1
            raise KernelUnavailable(error)
        self._thread = threading.Thread(target=self._read_loop, name="fanotify", daemon=True)
        self._thread.start()

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._fd], [], [], 0.2)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                data = os.read(self._fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                break
            for kind, pid, path in self.decode_buffer(data):
                with self._lock:
                    allowed = pid in self._pids
                if not allowed:
                    continue
                event = KernelFileEvent(
                    ts=time.time(),
                    pid=pid,
                    kind=kind,
                    path=path,
                    mode="w" if kind == "write" else ("r" if kind == "read" else ""),
                )
                try:
                    self._queue.put_nowait(event)
                except queue.Full:
                    self._error = "fanotify 事件队列已满，可能开始丢事件"
                    return

    @staticmethod
    def decode_buffer(data: bytes) -> List[Tuple[str, int, str]]:
        result: List[Tuple[str, int, str]] = []
        offset = 0
        while offset + 24 <= len(data):
            try:
                event_len, _vers, _reserved, _meta_len, mask, event_fd, pid = struct.unpack_from(
                    "=IBBHQii", data, offset
                )
            except struct.error:
                break
            if event_len < 24:
                break
            if event_fd >= 0:
                try:
                    path = os.readlink("/proc/self/fd/%d" % event_fd)
                except OSError:
                    path = ""
                try:
                    os.close(event_fd)
                except OSError:
                    pass
                if path.endswith(" (deleted)"):
                    path = path[: -len(" (deleted)")]
                if path:
                    for kind in fanotify_kinds(mask):
                        result.append((kind, int(pid), path))
            offset += event_len
        return result

    def update_pids(self, pids: Set[int]) -> None:
        with self._lock:
            self._pids = set(pids)

    def drain(self) -> List[KernelFileEvent]:
        result: List[KernelFileEvent] = []
        while True:
            try:
                result.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return result

    @property
    def last_error(self) -> str:
        return self._error

    @property
    def healthy(self) -> bool:
        return (
            self._fd >= 0
            and self._thread is not None
            and self._thread.is_alive()
        )

    def close(self) -> None:
        self._stop.set()
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


def make_kernel_source(
    mark_paths: Sequence[str] = ("/",),
    include_writes: bool = True,
) -> KernelSource:
    if sys.platform == "darwin":
        return MacEsloggerSource(include_writes=include_writes)
    if sys.platform.startswith("linux"):
        return LinuxFanotifySource(mark_paths=mark_paths, include_writes=include_writes)
    raise KernelUnavailable("当前平台没有内核事件后端")
