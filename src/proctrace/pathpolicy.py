"""Workspace / sensitive-path audit for AI-agent file access.

The monitor never reads file contents.  It only evaluates the path and access
mode of an already-open file descriptor, which is enough to flag "this agent
opened ~/.ssh/id_rsa" without turning proctrace into a DLP data reader.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import AuditConfig

# Runtime and system paths are allowed by default.  They are intentionally
# broad; the deny list below is evaluated first and catches the high-signal
# locations.  Users can disable these defaults with audit.use_defaults=false.
DEFAULT_ALLOW_PATTERNS: Tuple[str, ...] = (
    # macOS
    "/System/**",
    "/System/Volumes/**",
    "/Library/**",
    "/Applications/**",
    "/usr/**",
    "/bin/**",
    "/sbin/**",
    "/opt/homebrew/**",
    "/opt/local/**",
    "/opt/**",
    "/usr/local/**",
    "/private/var/folders/**",
    "/var/folders/**",
    "/private/tmp/**",
    "/tmp/**",
    "/private/etc/**",
    "/etc/**",
    "/dev/**",
    "/private/var/db/**",
    "/private/var/run/**",
    "~/Library/Caches/**",
    # Linux
    "/lib/**",
    "/lib32/**",
    "/lib64/**",
    "/opt/**",
    "/nix/store/**",
    "/proc/**",
    "/sys/**",
    "/run/**",
    "/var/tmp/**",
    "/var/cache/**",
    "/snap/**",
    "~/.cache/**",
    "~/.npm/**",
    "~/.bun/**",
    "~/.cargo/registry/**",
    "~/.rustup/**",
)

# High-signal secrets / browser profiles / agent credentials.  Deny wins over
# allow and workspace by design.
DEFAULT_DENY_PATTERNS: Tuple[str, ...] = (
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.kube/**",
    "~/.docker/config.json",
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/.git-credentials",
    "~/.config/gh/hosts.yml",
    "~/.config/gcloud/**",
    "~/.config/google-chrome/**",
    "~/.config/chromium/**",
    "~/.config/BraveSoftware/**",
    "~/.mozilla/firefox/**",
    "~/Library/Keychains/**",
    "/Library/Keychains/**",
    "~/.local/share/keyrings/**",
    "~/.password-store/**",
    "~/Library/Application Support/Google/Chrome/**",
    "~/Library/Application Support/Firefox/**",
    "~/Library/Application Support/Arc/**",
    "~/Library/Application Support/BraveSoftware/**",
    "~/Library/Safari/**",
    "~/.codex/auth.json",
    "~/.claude/.credentials.json",
    "**/.env",
    "**/.env.local",
    "**/.env.production",
    "**/.env.development",
    "**/.env.test",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa",
    "**/id_ed25519",
    "**/credentials.json",
    "**/secrets.json",
    "/etc/shadow",
    "/private/etc/shadow",
    "/etc/sudoers",
    "/proc/[0-9]*/mem",
    "/proc/[0-9]*/environ",
)


@dataclass(frozen=True)
class PathVerdict:
    reason: str  # "denied_path" or "outside_workspace"
    pattern: str = ""

    @property
    def detail(self) -> str:
        if self.reason == "denied_path":
            return "matches denied/sensitive path rule: %s" % self.pattern
        return "outside configured workspace"


def _expand(value: str) -> str:
    value = os.path.expandvars(os.path.expanduser(value))
    return os.path.normpath(value)


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


class PathAudit:
    def __init__(
        self,
        config: AuditConfig,
        default_workspace: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> None:
        self.config = config
        self.enabled = bool(config.enabled)
        self.platform = platform or sys.platform
        self.casefold = self.platform == "darwin"
        self.warnings: List[str] = []

        workspaces = list(config.workspaces)
        if not workspaces and default_workspace:
            workspaces = [default_workspace]
        self.workspaces: List[str] = []
        self.workspace_display: List[str] = []
        for value in workspaces:
            expanded = os.path.abspath(_expand(value))
            if expanded not in self.workspace_display:
                self.workspace_display.append(expanded)
            for candidate in (expanded, os.path.realpath(expanded)):
                if candidate not in self.workspaces:
                    self.workspaces.append(candidate)
        if self.enabled and config.outside_workspace and not self.workspaces:
            self.warnings.append(
                "audit.outside_workspace is on but no workspace is configured; "
                "pass --workspace PATH"
            )
        for workspace in self.workspace_display:
            if workspace == os.path.expanduser("~"):
                self.warnings.append(
                    "workspace is the home directory; files elsewhere in home "
                    "will be considered authorized"
                )
            if workspace == os.sep:
                self.warnings.append(
                    "workspace is /; outside-workspace auditing is effectively disabled"
                )

        self.allow_patterns: List[str] = [_expand(p) for p in config.allow_paths]
        self.deny_patterns: List[str] = [_expand(p) for p in config.deny_paths]
        self.ignore_patterns: List[str] = [_expand(p) for p in config.ignore_paths]
        if config.use_defaults:
            self.allow_patterns = _dedupe(
                [_expand(p) for p in DEFAULT_ALLOW_PATTERNS] + self.allow_patterns
            )
            self.deny_patterns = _dedupe(
                [_expand(p) for p in DEFAULT_DENY_PATTERNS] + self.deny_patterns
            )
        self.outside_workspace = bool(config.outside_workspace)
        self.include_stdio = bool(config.include_stdio)
        self._cache: Dict[Tuple[str, str], Optional[PathVerdict]] = {}
        self._real_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------ public
    def evaluate(self, path: str, kind: str = "file") -> Optional[PathVerdict]:
        if not self.enabled or kind not in ("file", "dir") or not path:
            return None
        if path.startswith(("socket:[", "pipe:[", "anon_inode:", "memfd:")):
            return None
        key = (path, kind)
        if key in self._cache:
            return self._cache[key]
        verdict = self._evaluate(path)
        if len(self._cache) > 20000:
            self._cache.clear()
            self._real_cache.clear()
        self._cache[key] = verdict
        return verdict

    def is_violation(self, path: str, kind: str = "file") -> bool:
        return self.evaluate(path, kind) is not None

    def summary(self) -> str:
        if not self.enabled:
            return "audit=off"
        ws = ", ".join(self.workspace_display) if self.workspace_display else "(none)"
        return "audit=on workspace=%s deny_rules=%d outside=%s" % (
            ws,
            len(self.deny_patterns),
            "on" if self.outside_workspace else "off",
        )

    # ----------------------------------------------------------------- internal
    def _evaluate(self, path: str) -> Optional[PathVerdict]:
        candidates = self._candidates(path)
        for candidate in candidates:
            for pattern in self.ignore_patterns:
                if self._match(candidate, pattern):
                    return None
        for candidate in candidates:
            for pattern in self.deny_patterns:
                if self._match(candidate, pattern):
                    return PathVerdict("denied_path", pattern)
        if any(self._in_workspace(candidate) for candidate in candidates):
            return None
        for candidate in candidates:
            for pattern in self.allow_patterns:
                if self._match(candidate, pattern):
                    return None
        if self.outside_workspace:
            return PathVerdict("outside_workspace", "")
        return None

    def _candidates(self, path: str) -> List[str]:
        expanded = _expand(path)
        candidates = [os.path.normpath(expanded)]
        real = self._real_cache.get(expanded)
        if real is None:
            try:
                real = os.path.realpath(expanded)
            except OSError:
                real = expanded
            self._real_cache[expanded] = real
        if real not in candidates:
            candidates.append(real)
        return candidates

    def _match(self, path: str, pattern: str) -> bool:
        if self.casefold:
            return fnmatch.fnmatchcase(path.lower(), pattern.lower())
        return fnmatch.fnmatchcase(path, pattern)

    def _in_workspace(self, path: str) -> bool:
        for workspace in self.workspaces:
            if self.casefold:
                path_cmp = path.lower()
                ws_cmp = workspace.lower()
            else:
                path_cmp = path
                ws_cmp = workspace
            if path_cmp == ws_cmp:
                return True
            prefix = ws_cmp.rstrip(os.sep) + os.sep
            if path_cmp.startswith(prefix):
                return True
        return False


def path_audit_from_config(
    config: AuditConfig,
    default_workspace: Optional[str],
    platform: Optional[str] = None,
) -> PathAudit:
    return PathAudit(config, default_workspace=default_workspace, platform=platform)
