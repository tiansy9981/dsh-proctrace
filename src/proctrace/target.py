"""Target process selection."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

import psutil


class TargetError(ValueError):
    pass


@dataclass
class Target:
    pid: int
    name: str = ""
    exe: str = ""
    cmdline: List[str] = field(default_factory=list)
    create_time: float = 0.0
    cwd: str = ""
    notes: List[str] = field(default_factory=list)

    def label(self) -> str:
        bits = ["%d" % self.pid]
        if self.name:
            bits.append(self.name)
        if self.exe and self.exe not in ("", "?"):
            bits.append(self.exe)
        return " ".join(bits)


def _info(proc: "psutil.Process") -> Target:
    try:
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        name = ""
    try:
        exe = proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        exe = ""
    try:
        cmdline = proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        cmdline = []
    try:
        create_time = proc.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        create_time = 0.0
    try:
        cwd = proc.cwd()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        cwd = ""
    return Target(
        pid=proc.pid,
        name=name or "",
        exe=exe or "",
        cmdline=cmdline or [],
        create_time=create_time or 0.0,
        cwd=cwd or "",
    )


def resolve_target(
    pid: Optional[int] = None,
    name: Optional[str] = None,
    cmdline: Optional[str] = None,
) -> Target:
    selectors = [x for x in (pid is not None, bool(name), bool(cmdline)) if x]
    if len(selectors) != 1:
        raise TargetError("请且只指定一种目标：--pid、--name 或 --cmdline")
    if pid is not None:
        if pid <= 0:
            raise TargetError("--pid 必须是正整数")
        try:
            proc = psutil.Process(pid)
            proc.create_time()
        except psutil.NoSuchProcess:
            raise TargetError("进程 %d 不存在" % pid)
        except psutil.AccessDenied:
            raise TargetError("无权限访问进程 %d" % pid)
        if proc.pid == os.getpid():
            raise TargetError("不能监控 proctrace 自身（pid %d）" % pid)
        return _info(proc)

    if name:
        pattern = name
        matches = []
        for proc in psutil.process_iter():
            if proc.pid == os.getpid():
                continue
            try:
                pname = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if fnmatch.fnmatchcase(pname, pattern) or fnmatch.fnmatchcase(
                pname.lower(), pattern.lower()
            ):
                matches.append(proc)
        if not matches:
            raise TargetError("没有进程名匹配 %r" % pattern)
        infos = [_info(p) for p in matches]
        infos.sort(key=lambda t: (t.create_time, t.pid), reverse=True)
        chosen = infos[0]
        if len(infos) > 1:
            others = ", ".join("%d(%s)" % (t.pid, t.name) for t in infos[1:8])
            chosen.notes.append(
                "matched %d processes; chose newest %d(%s); others: %s"
                % (len(infos), chosen.pid, chosen.name, others)
            )
        return chosen

    assert cmdline is not None
    try:
        regex = re.compile(cmdline)
    except re.error as exc:
        raise TargetError("--cmdline 正则无效: %s" % exc)
    matches = []
    for proc in psutil.process_iter():
        if proc.pid == os.getpid():
            continue
        try:
            joined = " ".join(proc.cmdline())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if regex.search(joined):
            matches.append(proc)
    if not matches:
        raise TargetError("没有命令行匹配 %r 的进程" % cmdline)
    infos = [_info(p) for p in matches]
    infos.sort(key=lambda t: (t.create_time, t.pid), reverse=True)
    chosen = infos[0]
    if len(infos) > 1:
        others = ", ".join("%d(%s)" % (t.pid, t.name) for t in infos[1:8])
        chosen.notes.append(
            "matched %d processes; chose newest %d(%s); others: %s"
            % (len(infos), chosen.pid, chosen.name, others)
        )
    return chosen
