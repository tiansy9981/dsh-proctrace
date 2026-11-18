"""Per-platform file-descriptor collection.

Linux uses procfs directly: one directory read plus one readlink per fd, and
fdinfo only for newly observed fds.  macOS uses libproc through psutil, which
is the fastest unprivileged API available there.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional, Tuple

from .model import FdInfo


class ProcessGone(Exception):
    pass


class AccessDenied(Exception):
    pass


class BackendUnavailable(Exception):
    pass


def classify_raw(raw: str) -> FdInfo:
    """Turn a /proc/<pid>/fd readlink result into an FdInfo skeleton."""
    path = raw
    deleted = False
    if path.endswith(" (deleted)") and not path.startswith("socket:["):
        path = path[: -len(" (deleted)")]
        deleted = True
    if path.startswith("socket:["):
        kind = "socket"
    elif path.startswith("pipe:["):
        kind = "pipe"
    elif path.startswith("anon_inode:"):
        kind = "anon"
    elif path.startswith("/"):
        kind = "file"
    else:
        kind = "other"
    return FdInfo(fd=-1, path=path, kind=kind, mode="", deleted=deleted, detail="")


def _mode_from_flags(flags: int) -> str:
    access = flags & 0o3
    return {0: "r", 1: "w", 2: "rw"}.get(access, "")


def _mac_mode(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    # psutil versions/platforms report either "r"/"w"/"rw" or fopen modes.
    if value in ("r", "w", "rw", "r+", "w+"):
        return "rw" if "+" in value or value == "rw" else value
    if value in ("a", "a+"):
        return "w" if value == "a" else "rw"
    return value


class Collector:
    name = "base"
    supports_procfs = False
    supports_pidfd = False
    supports_ptrace = False

    def list_fds(self, pid: int) -> Dict[int, FdInfo]:
        raise NotImplementedError

    def describe(self, pid: int, info: FdInfo) -> FdInfo:
        """Return the same FdInfo with optional mode/target details filled."""
        return info

    def capabilities(self) -> List[str]:
        caps = ["open-files"]
        if self.supports_procfs:
            caps.append("procfs-access")
        if self.supports_pidfd:
            caps.append("pidfd-target")
        if self.supports_ptrace:
            caps.append("ptrace-relation")
        return caps


class LinuxProcCollector(Collector):
    name = "linux-procfs"
    supports_procfs = True
    supports_pidfd = True
    supports_ptrace = True

    def __init__(self, proc_root: str = "/proc") -> None:
        self.proc_root = proc_root
        if not os.path.isdir(os.path.join(proc_root, "self", "fd")):
            raise BackendUnavailable("%s 不可用（需要挂载 procfs）" % proc_root)

    def _status_path(self, pid: int) -> str:
        return os.path.join(self.proc_root, str(pid), "status")

    def _read_status(self, pid: int) -> Dict[str, str]:
        result: Dict[str, str] = {}
        try:
            with open(self._status_path(pid), "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        result[key.strip()] = value.strip()
        except (OSError, ValueError):
            return result
        return result

    def list_fds(self, pid: int) -> Dict[int, FdInfo]:
        base = os.path.join(self.proc_root, str(pid), "fd")
        try:
            names = os.listdir(base)
        except FileNotFoundError:
            raise ProcessGone("pid %d 已退出" % pid)
        except PermissionError:
            raise AccessDenied("无权限读取 %s（尝试以相同用户运行）" % base)
        except OSError as exc:
            raise AccessDenied("读取 %s 失败: %s" % (base, exc))
        result: Dict[int, FdInfo] = {}
        for name in names:
            if not name.isdigit():
                continue
            fd = int(name)
            try:
                raw = os.readlink(os.path.join(base, name))
            except FileNotFoundError:
                continue  # closed while we were scanning
            except PermissionError:
                continue
            except OSError:
                continue
            info = classify_raw(raw)
            info = FdInfo(
                fd=fd,
                path=info.path,
                kind=info.kind,
                mode="",
                deleted=info.deleted,
                target_pid=None,
                detail="",
            )
            result[fd] = info
        return result

    def describe(self, pid: int, info: FdInfo) -> FdInfo:
        fdinfo = os.path.join(self.proc_root, str(pid), "fdinfo", str(info.fd))
        flags = None
        target_pid = None
        pos = None
        try:
            with open(fdinfo, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.startswith("flags:"):
                        try:
                            flags = int(line.split(":", 1)[1].strip(), 8)
                        except ValueError:
                            flags = None
                    elif line.startswith("pos:"):
                        pos = line.split(":", 1)[1].strip()
                    elif line.startswith("Pid:"):
                        try:
                            target_pid = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            target_pid = None
        except (OSError, ValueError):
            return info
        mode = _mode_from_flags(flags) if flags is not None else info.mode
        detail = info.detail
        if info.kind == "anon" and "pidfd" in info.path:
            detail = "pidfd"
        if pos is not None and info.kind == "file":
            detail = ("offset=%s" % pos) if not detail else detail + " offset=" + pos
        return FdInfo(
            fd=info.fd,
            path=info.path,
            kind=info.kind,
            mode=mode,
            deleted=info.deleted,
            target_pid=target_pid if target_pid and target_pid > 0 else info.target_pid,
            detail=detail,
        )

    def ptrace_tracer(self, pid: int) -> Optional[int]:
        """TracerPid of ``pid`` (Linux only)."""
        status = self._read_status(pid)
        try:
            tracer = int(status.get("TracerPid", "0"))
        except ValueError:
            return None
        return tracer if tracer > 0 else None


class MacPsutilCollector(Collector):
    name = "macos-libproc"
    supports_procfs = False
    supports_pidfd = False
    supports_ptrace = False

    def __init__(self) -> None:
        try:
            import psutil
        except ImportError as exc:  # pragma: no cover
            raise BackendUnavailable("缺少 psutil: %s" % exc)
        self.psutil = psutil
        self._cache: Dict[int, Tuple[float, object]] = {}

    def _process(self, pid: int):
        try:
            proc = self.psutil.Process(pid)
            create_time = proc.create_time()
        except self.psutil.NoSuchProcess:
            raise ProcessGone("pid %d 已退出" % pid)
        except self.psutil.AccessDenied as exc:
            raise AccessDenied("无法访问 pid %d: %s" % (pid, exc))
        cached = self._cache.get(pid)
        if cached and cached[0] == create_time:
            return cached[1]
        self._cache[pid] = (create_time, proc)
        return proc

    def forget(self, pid: int) -> None:
        self._cache.pop(pid, None)

    def list_fds(self, pid: int) -> Dict[int, FdInfo]:
        proc = self._process(pid)
        try:
            entries = proc.open_files()
        except self.psutil.NoSuchProcess:
            self.forget(pid)
            raise ProcessGone("pid %d 已退出" % pid)
        except self.psutil.ZombieProcess:
            raise ProcessGone("pid %d 是僵尸进程" % pid)
        except self.psutil.AccessDenied as exc:
            raise AccessDenied("无权限读取 pid %d 的 fd: %s" % (pid, exc))
        except OSError as exc:
            raise AccessDenied("读取 pid %d 的 fd 失败: %s" % (pid, exc))
        result: Dict[int, FdInfo] = {}
        for entry in entries:
            fd = getattr(entry, "fd", -1)
            if fd is None or fd < 0:
                continue
            path = getattr(entry, "path", "") or ""
            if not path:
                continue
            mode = _mac_mode(getattr(entry, "mode", "") or "")
            result[fd] = FdInfo(fd=fd, path=path, kind="file", mode=mode)
        return result


def make_collector(preferred: str = "auto") -> Collector:
    platform = sys.platform
    if preferred not in ("auto", "procfs", "psutil"):
        raise BackendUnavailable("未知 backend: %s" % preferred)

    if platform.startswith("linux"):
        if preferred in ("auto", "procfs"):
            return LinuxProcCollector()
        if preferred == "psutil":
            return _make_psutil_collector()
        raise BackendUnavailable("Linux 不支持 backend=%s" % preferred)
    if platform == "darwin":
        if preferred in ("auto", "psutil"):
            return MacPsutilCollector()
        if preferred == "procfs":
            raise BackendUnavailable("macOS 没有 procfs，请使用 --backend psutil")
        raise BackendUnavailable("macOS 不支持 backend=%s" % preferred)
    raise BackendUnavailable(
        "暂不支持平台 %s；目前支持 Linux 和 macOS" % platform
    )


def _make_psutil_collector() -> Collector:
    """Generic psutil fallback, used only on Linux when requested."""
    try:
        import psutil
    except ImportError as exc:  # pragma: no cover
        raise BackendUnavailable("缺少 psutil: %s" % exc)

    class PsutilCollector(Collector):
        name = "psutil"
        supports_ptrace = True

        def list_fds(self, pid: int) -> Dict[int, FdInfo]:
            try:
                proc = psutil.Process(pid)
                entries = proc.open_files()
            except psutil.NoSuchProcess:
                raise ProcessGone("pid %d 已退出" % pid)
            except psutil.AccessDenied as exc:
                raise AccessDenied(str(exc))
            except psutil.ZombieProcess:
                raise ProcessGone("pid %d 是僵尸进程" % pid)
            result: Dict[int, FdInfo] = {}
            for entry in entries:
                fd = getattr(entry, "fd", -1)
                path = getattr(entry, "path", "") or ""
                if fd is None or fd < 0 or not path:
                    continue
                mode = _mac_mode(getattr(entry, "mode", "") or "")
                result[fd] = FdInfo(fd=fd, path=path, kind="file", mode=mode)
            return result

        def ptrace_tracer(self, pid: int) -> Optional[int]:
            try:
                with open("/proc/%d/status" % pid, "r", encoding="utf-8", errors="replace") as h:
                    for line in h:
                        if line.startswith("TracerPid:"):
                            return int(line.split(":", 1)[1])
            except (OSError, ValueError):
                return None
            return None

    return PsutilCollector()
