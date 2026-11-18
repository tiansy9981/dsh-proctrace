"""Protected/exclude process rules.

A rule is an AND of all fields that are present.  This keeps configuration
predictable: ``{"name": "ssh", "uid": 501}`` means "an ssh process owned by
uid 501", not "ssh or uid 501".
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Sequence, Set

from .model import ProcessInfo

RULE_KEYS = {"pid", "name", "exe", "cmdline", "uid", "create_time"}


class ConfigError(ValueError):
    pass


def _as_int(value, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("%s 必须是整数" % field_name)
    return value


@dataclass
class Rule:
    pid: Optional[int] = None
    name: Optional[str] = None
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    uid: Optional[int] = None
    create_time: Optional[float] = None
    _cmdline_re: Optional["re.Pattern"] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.pid is not None and self.pid <= 0:
            raise ConfigError("rule.pid 必须是正整数")
        if self.uid is not None and self.uid < 0:
            raise ConfigError("rule.uid 不能为负数")
        if self.create_time is not None and self.pid is None:
            raise ConfigError("rule.create_time 只能和 pid 一起使用")
        if self.cmdline is not None:
            try:
                self._cmdline_re = re.compile(self.cmdline)
            except re.error as exc:
                raise ConfigError("无效的 cmdline 正则 %r: %s" % (self.cmdline, exc))

    @classmethod
    def from_dict(cls, data: dict, where: str = "rule") -> "Rule":
        if not isinstance(data, dict):
            raise ConfigError("%s 必须是对象" % where)
        unknown = set(data) - RULE_KEYS
        if unknown:
            raise ConfigError("%s 含未知字段: %s" % (where, ", ".join(sorted(unknown))))
        if not data:
            raise ConfigError("%s 不能为空" % where)
        kwargs = {}
        if "pid" in data:
            kwargs["pid"] = _as_int(data["pid"], where + ".pid")
        if "uid" in data:
            kwargs["uid"] = _as_int(data["uid"], where + ".uid")
        if "create_time" in data:
            ct = data["create_time"]
            if isinstance(ct, bool) or not isinstance(ct, (int, float)):
                raise ConfigError("%s.create_time 必须是数字" % where)
            kwargs["create_time"] = float(ct)
        for key in ("name", "exe", "cmdline"):
            if key in data:
                value = data[key]
                if not isinstance(value, str) or not value:
                    raise ConfigError("%s.%s 必须是非空字符串" % (where, key))
                kwargs[key] = value
        try:
            return cls(**kwargs)
        except ConfigError as exc:
            raise ConfigError("%s: %s" % (where, exc))

    def matches(self, proc: ProcessInfo) -> bool:
        if self.pid is not None and proc.pid != self.pid:
            return False
        if self.create_time is not None and abs(proc.create_time - self.create_time) > 1.0:
            return False
        if self.uid is not None and proc.uid != self.uid:
            return False
        if self.name is not None and not fnmatch.fnmatchcase(proc.name or "", self.name):
            return False
        if self.exe is not None and not fnmatch.fnmatchcase(proc.exe or "", self.exe):
            return False
        if self._cmdline_re is not None:
            joined = " ".join(proc.cmdline or [])
            if not self._cmdline_re.search(joined):
                return False
        return True

    def is_pid_only(self) -> bool:
        # A create_time check needs the real process metadata, so such a rule
        # must go through the full policy scan and cannot be applied blindly.
        return (
            self.pid is not None
            and self.create_time is None
            and all(v is None for v in (self.name, self.exe, self.cmdline, self.uid))
        )

    def describe(self) -> str:
        parts = []
        for key in ("pid", "name", "exe", "cmdline", "uid"):
            value = getattr(self, key)
            if value is not None:
                parts.append("%s=%s" % (key, value))
        if self.create_time is not None:
            parts.append("create_time=%.3f" % self.create_time)
        return " ".join(parts)

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {}
        for key in ("pid", "name", "exe", "cmdline", "uid", "create_time"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


@dataclass
class PolicyMatch:
    protected: Dict[int, ProcessInfo] = field(default_factory=dict)
    excluded: Set[int] = field(default_factory=set)
    protected_rules: Dict[int, str] = field(default_factory=dict)
    excluded_rules: Dict[int, str] = field(default_factory=dict)

    def protected_pids(self) -> Set[int]:
        return set(self.protected)


class Policy:
    def __init__(self, protected: Sequence[Rule], exclude: Sequence[Rule]):
        self.protected_rules = list(protected)
        self.exclude_rules = list(exclude)
        self._match = PolicyMatch()
        self._last_error: Optional[str] = None

    @property
    def needs_full_scan(self) -> bool:
        rules = self.protected_rules + self.exclude_rules
        return any(not rule.is_pid_only() for rule in rules)

    @property
    def has_rules(self) -> bool:
        return bool(self.protected_rules or self.exclude_rules)

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    def resolve(self, all_procs: Optional[Iterable[ProcessInfo]] = None) -> PolicyMatch:
        """Recompute protected/excluded PIDs.

        ``all_procs`` is required for name/exe/cmdline/uid rules.  When only
        PID rules exist the caller may pass None and the rules are applied
        directly.
        """
        match = PolicyMatch()
        self._last_error = None
        procs = list(all_procs) if all_procs is not None else []
        for rule in self.protected_rules:
            if procs:
                for proc in procs:
                    if rule.matches(proc):
                        match.protected[proc.pid] = proc
                        match.protected_rules[proc.pid] = rule.describe()
            elif rule.is_pid_only() and rule.pid is not None:
                # Direct PID rule: create a minimal placeholder.  Details are
                # resolved lazily when an alert is emitted.
                match.protected[rule.pid] = ProcessInfo(pid=rule.pid)
                match.protected_rules[rule.pid] = rule.describe()
        for rule in self.exclude_rules:
            if procs:
                for proc in procs:
                    if rule.matches(proc):
                        match.excluded.add(proc.pid)
                        match.excluded_rules[proc.pid] = rule.describe()
            elif rule.is_pid_only() and rule.pid is not None:
                match.excluded.add(rule.pid)
                match.excluded_rules[rule.pid] = rule.describe()
        self._match = match
        return match

    @property
    def match(self) -> PolicyMatch:
        return self._match

    def match_protected(self, proc: ProcessInfo) -> Optional[Rule]:
        for rule in self.protected_rules:
            if rule.matches(proc):
                return rule
        return None

    def match_excluded(self, proc: ProcessInfo) -> Optional[Rule]:
        for rule in self.exclude_rules:
            if rule.matches(proc):
                return rule
        return None

    def is_protected_pid(self, pid: int) -> bool:
        return pid in self._match.protected

    def is_excluded_pid(self, pid: int) -> bool:
        return pid in self._match.excluded

    def protected_name(self, pid: int) -> str:
        proc = self._match.protected.get(pid)
        if proc is None:
            return ""
        return proc.name or ""

    def describe(self) -> str:
        return "protected=%d exclude=%d" % (
            len(self._match.protected),
            len(self._match.excluded),
        )


def rule_from_cli_pid(pid: int) -> Rule:
    return Rule(pid=pid)


def rule_from_cli_name(name: str) -> Rule:
    return Rule(name=name)


def current_uid() -> int:
    try:
        return os.geteuid()
    except AttributeError:  # pragma: no cover - Windows only
        return os.getuid()
