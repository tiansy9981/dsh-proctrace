"""The polling monitor: process tree, fd diffing, and policy alerts."""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Sequence, Set, Tuple

import psutil

from . import __version__
from .collector import AccessDenied, Collector, ProcessGone
from .config import Config
from .database import database_operation, database_service
from .db_audit import DbAuditSource
from .kernel import KernelSource
from .model import Event, FdInfo, MonitorStats, ProcessInfo
from .network import NetworkMonitor
from .pathpolicy import PathAudit
from .policy import Policy, PolicyMatch

PROC_PATH_RE = re.compile(r"^/proc/(\d+)(?:/|$)")


class TargetGone(Exception):
    pass


class TargetRejected(Exception):
    pass


def _safe_uid(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value.real)
    except AttributeError:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


def proc_from_psutil(proc: "psutil.Process", with_cmdline: bool = True) -> ProcessInfo:
    attrs = ["pid", "ppid", "name", "exe", "uids", "create_time"]
    if with_cmdline:
        attrs.append("cmdline")
    try:
        data = proc.as_dict(attrs=attrs, ad_value=None)
    except psutil.NoSuchProcess:
        raise
    except (psutil.AccessDenied, psutil.ZombieProcess):
        data = {"pid": proc.pid}
    return ProcessInfo(
        pid=int(data.get("pid") or proc.pid),
        ppid=int(data.get("ppid") or 0),
        name=str(data.get("name") or ""),
        exe=str(data.get("exe") or ""),
        cmdline=[str(x) for x in (data.get("cmdline") or [])],
        uid=_safe_uid(data.get("uids")),
        create_time=float(data.get("create_time") or 0.0),
    )


class Monitor:
    def __init__(
        self,
        root_pid: int,
        collector: Collector,
        config: Config,
        policy: Optional[Policy] = None,
        follow_children: bool = True,
        show_initial: Optional[bool] = None,
        max_processes: Optional[int] = None,
        path_audit: Optional[PathAudit] = None,
        kernel_source: Optional[KernelSource] = None,
        db_audit_source: Optional[DbAuditSource] = None,
    ) -> None:
        self.root_pid = int(root_pid)
        self.collector = collector
        self.config = config
        self.policy = policy or Policy([], [])
        self.follow_children = follow_children
        self.show_initial = config.show_initial if show_initial is None else show_initial
        self.max_processes = max_processes or config.max_processes
        self.interval = config.interval
        self.path_audit = path_audit
        self.network_monitor = (
            NetworkMonitor(config.network) if config.network.enabled else None
        )
        self.kernel_source = kernel_source
        self.db_audit_source = db_audit_source

        self.processes: Dict[int, ProcessInfo] = {}
        self.files: Dict[int, Dict[int, FdInfo]] = {}
        self.stats = MonitorStats()
        self.started_at = time.time()
        self.target_gone = False
        self.initial_poll_done = False
        self.policy_match: PolicyMatch = PolicyMatch()

        self._root_create_time: Optional[float] = None
        self._last_policy_refresh = 0.0
        self._cached_tree: Optional[List[ProcessInfo]] = None
        self._last_tree_refresh = 0.0
        self._policy_scan_seconds = 0.0
        self._warned: Set[str] = set()
        self._proc_errors: Dict[int, str] = {}
        self._protected_alerts: Dict[Tuple[int, int], Tuple[int, str]] = {}
        self._path_alerts: Dict[Tuple[int, int], Tuple[str, str, str]] = {}
        self._db_file_events: Set[Tuple[int, int, str]] = set()
        self._path_violation_seen: Set[Tuple[int, str, str, str]] = set()
        self._db_file_seen: Set[Tuple[int, str, str, str]] = set()
        self._ptrace_seen: Set[Tuple[int, int]] = set()
        self._ptrace_cache: Dict[int, Tuple[float, Optional[int]]] = {}

    # ------------------------------------------------------------------ public
    def preflight(self) -> List[Event]:
        """Resolve policy once so configuration errors surface before the UI."""
        events: List[Event] = []
        self._refresh_policy(events)
        if self.root_pid in self.policy_match.excluded:
            raise TargetRejected("目标进程 %d 命中 exclude 规则，拒绝监控" % self.root_pid)
        if self.root_pid in self.policy_match.protected:
            raise TargetRejected(
                "目标进程 %d 命中 protected 规则，不能同时作为监控目标和保护对象"
                % self.root_pid
            )
        return events

    def poll(self) -> List[Event]:
        """Run one scan and return events produced by it."""
        started = time.perf_counter()
        events: List[Event] = []
        self.stats.polls += 1
        self._refresh_policy(events)

        try:
            tree = self._get_tree(events)
        except TargetGone:
            self._handle_target_gone(events)
            self._scan_db_audit(events)
            self.stats.events += len(events)
            self._finish_scan(started)
            return events
        if not tree:
            self._handle_target_gone(events)
            self._scan_db_audit(events)
            self.stats.events += len(events)
            self._finish_scan(started)
            return events

        self._apply_policy(tree, events)
        self._diff_processes(tree, events)
        self._scan_files(tree, events)
        self._scan_network(events)
        self._drain_kernel(events)
        self._scan_db_audit(events)
        self._check_ptrace(events)
        self.stats.process_count = len(self.processes)
        self.stats.fd_count = sum(p.fd_count for p in self.processes.values())
        self.stats.events += len(events)
        self.initial_poll_done = True
        self._finish_scan(started)
        return events

    def start_kernel(self) -> None:
        if self.kernel_source is not None:
            self.kernel_source.start()

    def close(self) -> None:
        if self.kernel_source is not None:
            self.kernel_source.close()
        if self.db_audit_source is not None:
            self.db_audit_source.close()

    def drain_supplemental(self) -> List[Event]:
        """Drain asynchronous audit sources after the target has exited."""
        events: List[Event] = []
        if self.db_audit_source is not None:
            self._scan_db_audit(events)
        self.stats.events += len(events)
        return events

    def files_for(self, pid: int) -> List[FdInfo]:
        return sorted(self.files.get(pid, {}).values(), key=lambda f: f.fd)

    def process_list(self) -> List[ProcessInfo]:
        return sorted(self.processes.values(), key=lambda p: (p.depth, p.pid))

    def capabilities(self) -> List[str]:
        caps = list(self.collector.capabilities())
        if self.path_audit is not None and self.path_audit.enabled:
            caps.append("path-audit")
        if self.network_monitor is not None and self.network_monitor.enabled:
            caps.append("network")
        if self.config.database.enabled:
            caps.append("database")
        if self.kernel_source is not None:
            caps.append("kernel:%s" % self.kernel_source.name)
        if self.db_audit_source is not None and self.db_audit_source.enabled:
            caps.append("db-audit")
        return caps

    def export(self) -> Dict[str, object]:
        procs = []
        for proc in self.process_list():
            procs.append(proc.to_dict(include_files=True, files=self.files_for(proc.pid)))
        return {
            "tool": "proctrace",
            "version": __version__,
            "generated_at": time.time(),
            "generated_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "target_pid": self.root_pid,
            "backend": self.collector.name,
            "capabilities": self.capabilities(),
            "stats": self.stats.to_dict(),
            "audit": self.path_audit.summary() if self.path_audit is not None else "audit=off",
            "connections": (
                [c.to_dict() for c in self.network_monitor.all_connections()]
                if self.network_monitor is not None
                else []
            ),
            "kernel": self.kernel_source.name if self.kernel_source is not None else "off",
            "db_audit": (
                "on" if self.db_audit_source is not None and self.db_audit_source.enabled else "off"
            ),
            "processes": procs,
        }

    # ------------------------------------------------------------------ policy
    def _refresh_policy(self, events: List[Event]) -> None:
        if not self.policy.has_rules:
            self.policy_match = PolicyMatch()
            return
        now = time.time()
        due = (
            self._last_policy_refresh == 0.0
            or now - self._last_policy_refresh >= self.config.policy_refresh
        )
        if not due:
            return
        scan_started = time.perf_counter()
        all_procs: Optional[List[ProcessInfo]] = None
        if self.policy.needs_full_scan:
            all_procs = self._scan_all_processes()
        self.policy_match = self.policy.resolve(all_procs)
        self._policy_scan_seconds = time.perf_counter() - scan_started
        self._last_policy_refresh = now
        if self.policy.last_error:
            self._warn("policy", "策略计算失败: %s" % self.policy.last_error, events)

    def _scan_all_processes(self) -> List[ProcessInfo]:
        result: List[ProcessInfo] = []
        attrs = ["pid", "ppid", "name", "exe", "cmdline", "uids", "create_time"]
        try:
            iterator = psutil.process_iter(attrs=attrs, ad_value=None)
        except TypeError:  # very old psutil
            iterator = psutil.process_iter()
        for proc in iterator:
            try:
                result.append(proc_from_psutil(proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return result

    def _apply_policy(self, tree: Sequence[ProcessInfo], events: List[Event]) -> None:
        match = self.policy_match
        by_pid = {p.pid: p for p in tree}
        # Apply rules to tree members immediately.  The full policy scan (for
        # victims outside the tree) is refreshed less often, but a newly
        # spawned child must never be scanned before its name/exe/cmdline rule
        # has had a chance to protect it.
        for proc in tree:
            if proc.pid not in match.protected:
                rule = self.policy.match_protected(proc)
                if rule is not None:
                    match.protected[proc.pid] = proc
                    match.protected_rules[proc.pid] = rule.describe()
            if proc.pid not in match.excluded:
                rule = self.policy.match_excluded(proc)
                if rule is not None:
                    match.excluded.add(proc.pid)
                    match.excluded_rules[proc.pid] = rule.describe()
        for proc in tree:
            proc.protected = proc.pid in match.protected
            proc.excluded = proc.pid in match.excluded
        # An excluded parent excludes its whole subtree.
        for proc in tree:
            if proc.excluded:
                continue
            parent = proc.ppid
            seen = set()
            while parent and parent in by_pid and parent not in seen:
                seen.add(parent)
                if parent in match.excluded:
                    proc.excluded = True
                    break
                parent = by_pid[parent].ppid
        if self.root_pid in match.excluded:
            raise TargetRejected("目标进程 %d 命中 exclude 规则，拒绝监控" % self.root_pid)
        if self.root_pid in match.protected:
            raise TargetRejected(
                "目标进程 %d 命中 protected 规则，不能同时作为监控目标和保护对象" % self.root_pid
            )
        # Materialise victim metadata for rules that only supplied a PID.
        for pid in list(match.protected):
            if not match.protected[pid].name:
                try:
                    p = psutil.Process(pid)
                    match.protected[pid] = proc_from_psutil(p, with_cmdline=False)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

    # -------------------------------------------------------------------- tree
    def _get_tree(self, events: List[Event]) -> List[ProcessInfo]:
        """Rebuild the tree at tree_refresh cadence; scan FDs more often.

        Discovering descendants is the expensive part with libproc (it walks
        the global process list), while reading a known PID's fds is cheap.
        New children therefore appear within tree_refresh seconds.
        """
        now = time.time()
        if (
            self._cached_tree is None
            or now - self._last_tree_refresh >= self.config.tree_refresh
        ):
            tree = self._build_tree(events)
            self._cached_tree = tree
            self._last_tree_refresh = now
            return tree
        return self._cached_tree

    def _build_tree(self, events: List[Event]) -> List[ProcessInfo]:
        try:
            root = psutil.Process(self.root_pid)
            root_create = root.create_time()
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            raise TargetGone()
        except psutil.AccessDenied:
            raise TargetGone()
        if self._root_create_time is None:
            self._root_create_time = root_create
        elif abs(root_create - self._root_create_time) > 1.0:
            raise TargetGone()

        raw = [root]
        if self.follow_children:
            try:
                raw.extend(root.children(recursive=True))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        except_errors = []
        infos: List[ProcessInfo] = []
        for proc in raw:
            try:
                infos.append(proc_from_psutil(proc))
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                except_errors.append(proc.pid)
                infos.append(ProcessInfo(pid=proc.pid, error="access denied"))
        if not infos:
            raise TargetGone()

        by_pid = {p.pid: p for p in infos}
        for proc in infos:
            depth = 0
            parent = proc.ppid
            seen = set()
            while parent in by_pid and parent != proc.pid and parent not in seen and depth < 128:
                seen.add(parent)
                depth += 1
                parent = by_pid[parent].ppid
            proc.depth = depth
        infos.sort(key=lambda p: (p.depth, p.pid))

        if len(infos) > self.max_processes:
            total = len(infos)
            infos = infos[: self.max_processes]
            self._warn(
                "tree-cap",
                "进程树共 %d 个进程，超过 max_processes=%d，只监控前 %d 个"
                % (total, self.max_processes, len(infos)),
                events,
            )
        for pid in except_errors:
            self._warn(
                "access-tree-%d" % pid,
                "无权限读取进程 %d 的信息" % pid,
                events,
            )
        return infos

    def _diff_processes(self, tree: Sequence[ProcessInfo], events: List[Event]) -> None:
        current = {p.pid: p for p in tree}
        previous = self.processes
        self.stats.fd_count = 0

        for pid, proc in current.items():
            old = previous.get(pid)
            if old is None:
                if self.initial_poll_done:
                    events.append(
                        self._event(
                            "process_start",
                            proc,
                            detail=" ".join(proc.cmdline)[:500],
                        )
                    )
                self.files.setdefault(pid, {})
            elif old.create_time and proc.create_time and abs(old.create_time - proc.create_time) > 1.0:
                events.append(
                    self._event("process_exit", old, detail="PID 被复用")
                )
                self._drop_process(pid)
                self.files[pid] = {}
                self._cached_tree = None
                events.append(
                    self._event("process_start", proc, detail="PID 复用后的新进程")
                )
            else:
                proc.started = old.started
                proc.fd_count = old.fd_count
                proc.error = old.error
        for pid in list(previous):
            if pid not in current:
                old = previous[pid]
                alive = True
                try:
                    psutil.Process(pid).create_time()
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    alive = False
                except psutil.AccessDenied:
                    alive = True
                detail = "" if not alive else "已离开被监控进程树（可能被 reparent）"
                events.append(self._event("process_exit", old, detail=detail))
                self._drop_process(pid)
        self.processes = current

    def _drop_process(self, pid: int) -> None:
        forget = getattr(self.collector, "forget", None)
        if forget is not None:
            try:
                forget(pid)
            except Exception:
                pass
        self.files.pop(pid, None)
        self.policy_match.protected.pop(pid, None)
        self.policy_match.protected_rules.pop(pid, None)
        self.policy_match.excluded.discard(pid)
        self.policy_match.excluded_rules.pop(pid, None)
        for key in [k for k in self._protected_alerts if k[0] == pid]:
            self._protected_alerts.pop(key, None)
        for key in [k for k in self._path_alerts if k[0] == pid]:
            self._path_alerts.pop(key, None)
        self._db_file_events = {k for k in self._db_file_events if k[0] != pid}
        self._path_violation_seen = {k for k in self._path_violation_seen if k[0] != pid}
        self._db_file_seen = {k for k in self._db_file_seen if k[0] != pid}
        if self.network_monitor is not None:
            self.network_monitor.clear_pid(pid)
        self._proc_errors.pop(pid, None)

    # ------------------------------------------------------------------- files
    def _scan_files(self, tree: Sequence[ProcessInfo], events: List[Event]) -> None:
        for proc in tree:
            if proc.excluded:
                proc.fd_count = 0
                self.files[proc.pid] = {}
                continue
            if proc.protected:
                # Deliberately do not open the protected process's fd table.
                proc.fd_count = 0
                self.files[proc.pid] = {}
                continue
            try:
                raw = self.collector.list_fds(proc.pid)
            except ProcessGone:
                if proc.pid == self.root_pid:
                    self._handle_target_gone(events)
                    break
                events.append(self._event("process_exit", proc, detail="扫描时进程已退出"))
                self._drop_process(proc.pid)
                self.processes.pop(proc.pid, None)
                self._cached_tree = None
                continue
            except AccessDenied as exc:
                msg = str(exc)
                if self._proc_errors.get(proc.pid) != msg:
                    self._proc_errors[proc.pid] = msg
                    proc.error = msg
                    self.stats.errors += 1
                    self._warn("access-%d" % proc.pid, msg, events)
                proc.fd_count = len(self.files.get(proc.pid, {}))
                continue
            except OSError as exc:
                msg = "读取 pid %d 失败: %s" % (proc.pid, exc)
                if self._proc_errors.get(proc.pid) != msg:
                    self._proc_errors[proc.pid] = msg
                    proc.error = msg
                    self.stats.errors += 1
                    self._warn("oserror-%d" % proc.pid, msg, events)
                continue

            self._proc_errors.pop(proc.pid, None)
            proc.error = ""
            previous = self.files.get(proc.pid, {})
            current: Dict[int, FdInfo] = {}
            for fd, incoming in raw.items():
                old = previous.get(fd)
                if old is not None and self._same_base(old, incoming):
                    if incoming.kind == "anon" and "pidfd" in incoming.path:
                        incoming = self.collector.describe(proc.pid, incoming)
                    # Carry details that the cheap listing does not repeat.
                    incoming = FdInfo(
                        fd=fd,
                        path=old.path,
                        kind=old.kind,
                        mode=incoming.mode or old.mode,
                        deleted=old.deleted,
                        target_pid=incoming.target_pid
                        if incoming.target_pid is not None
                        else old.target_pid,
                        detail=old.detail,
                    )
                    if old.target_pid != incoming.target_pid:
                        events.append(
                            self._event("change", proc, fd=fd, info=incoming)
                        )
                        self._reset_fd_alert(proc.pid, fd)
                        self._check_proc_access(proc, fd, incoming, events)
                        self._check_path_policy(proc, fd, incoming, events)
                    current[fd] = incoming
                    continue

                described = self.collector.describe(proc.pid, incoming)
                current[fd] = described
                kernel_mode = (
                    self.kernel_source is not None
                    and self.kernel_source.healthy
                    and self.initial_poll_done
                )
                if old is None:
                    if (self.show_initial or self.initial_poll_done) and not kernel_mode:
                        events.append(
                            self._event(
                                "open", proc, fd=fd, info=described, initial=not self.initial_poll_done
                            )
                        )
                else:
                    if not kernel_mode:
                        events.append(
                            self._event("change", proc, fd=fd, info=described, old=old)
                        )
                    self._reset_fd_alert(proc.pid, fd)
                self._check_proc_access(proc, fd, described, events)
                if not kernel_mode:
                    self._check_path_policy(proc, fd, described, events)
                    self._check_database_file(proc, fd, described, events)

            for fd, gone in previous.items():
                if fd not in current:
                    if not (
                        self.kernel_source is not None
                        and self.kernel_source.healthy
                        and self.initial_poll_done
                    ):
                        events.append(self._event("close", proc, fd=fd, info=gone))
                    self._reset_fd_alert(proc.pid, fd)
            self.files[proc.pid] = current
            proc.fd_count = len(current)

    @staticmethod
    def _same_base(a: FdInfo, b: FdInfo) -> bool:
        return a.path == b.path and a.kind == b.kind and a.deleted == b.deleted

    def _reset_fd_alert(self, pid: int, fd: int) -> None:
        self._protected_alerts.pop((pid, fd), None)
        self._path_alerts.pop((pid, fd), None)
        self._db_file_events = {k for k in self._db_file_events if not (k[0] == pid and k[1] == fd)}

    def _check_path_policy(
        self, proc: ProcessInfo, fd: int, info: FdInfo, events: List[Event]
    ) -> None:
        if self.path_audit is None or not self.path_audit.enabled:
            return
        if fd in (0, 1, 2) and not self.path_audit.include_stdio:
            return
        verdict = self.path_audit.evaluate(info.path, info.kind)
        if verdict is None:
            return
        key = (proc.pid, fd)
        current = (info.path, verdict.reason, verdict.pattern)
        if self._path_alerts.get(key) == current:
            return
        self._path_alerts[key] = current
        seen = (proc.pid, info.path, verdict.reason, verdict.pattern)
        if seen in self._path_violation_seen:
            return
        self._path_violation_seen.add(seen)
        self.stats.alerts += 1
        events.append(
            self._event(
                "violation",
                proc,
                fd=fd,
                info=info,
                reason=verdict.reason,
                via="path",
                detail=verdict.detail,
            )
        )

    def _drain_kernel(self, events: List[Event]) -> None:
        if self.kernel_source is None:
            return
        active = {
            pid
            for pid, proc in self.processes.items()
            if not proc.protected and not proc.excluded
        }
        self.kernel_source.update_pids(active)
        for raw in self.kernel_source.drain():
            proc = self.processes.get(raw.pid)
            if proc is None:
                continue
            info = FdInfo(
                fd=-1,
                path=raw.path,
                kind="file",
                mode=raw.mode,
                detail="kernel",
            )
            if raw.kind == "write" and not self.config.kernel.include_writes:
                continue
            events.append(
                self._event(
                    raw.kind,
                    proc,
                    info=info,
                    via="kernel",
                    detail="kernel event",
                )
            )
            if raw.kind in ("open", "read", "write") and self.path_audit is not None:
                verdict = self.path_audit.evaluate(raw.path, "file")
                if verdict is not None:
                    key = (raw.pid, raw.path, verdict.reason, verdict.pattern)
                    if key not in self._path_violation_seen:
                        self._path_violation_seen.add(key)
                        self.stats.alerts += 1
                        events.append(
                            self._event(
                                "violation",
                                proc,
                                info=info,
                                reason=verdict.reason,
                                via="kernel",
                                detail=verdict.detail,
                            )
                        )
            if raw.kind in ("open", "read", "write") and self.config.database.enabled:
                service = database_service(
                    raw.path, self.config.database.sqlite_suffixes
                )
                if service:
                    if raw.kind == "read":
                        operation = "read"
                    elif raw.kind == "write":
                        operation = "write"
                    else:
                        operation = database_operation(raw.mode)
                    key = (raw.pid, raw.path, service, operation)
                    if key not in self._db_file_seen:
                        self._db_file_seen.add(key)
                        events.append(
                            self._event(
                                "db_file",
                                proc,
                                info=info,
                                service=service,
                                reason=operation,
                                via="kernel",
                                detail="%s %s" % (service, operation),
                            )
                        )
        error = self.kernel_source.last_error
        if error:
            self._warn("kernel", "kernel source: %s" % error, events)

    def _check_database_file(
        self, proc: ProcessInfo, fd: int, info: FdInfo, events: List[Event]
    ) -> None:
        if not self.config.database.enabled or info.kind != "file":
            return
        service = database_service(info.path, self.config.database.sqlite_suffixes)
        if not service:
            return
        key = (proc.pid, fd, info.path)
        if key in self._db_file_events:
            return
        operation = database_operation(info.mode)
        seen = (proc.pid, info.path, service, operation)
        if seen in self._db_file_seen:
            return
        self._db_file_seen.add(seen)
        self._db_file_events.add(key)
        events.append(
            self._event(
                "db_file",
                proc,
                fd=fd,
                info=info,
                service=service,
                reason=operation,
                detail="%s %s" % (service, operation),
            )
        )

    def _scan_network(self, events: List[Event]) -> None:
        if self.network_monitor is None or not self.network_monitor.enabled:
            return
        pids = [
            pid
            for pid, proc in self.processes.items()
            if not proc.protected and not proc.excluded
        ]
        net_events, errors = self.network_monitor.poll(pids, show_initial=self.show_initial)
        for message in errors:
            self._warn("network-%s" % message, message, events)
        for net_event in net_events:
            proc = self.processes.get(net_event.conn.pid)
            if proc is None or proc.protected or proc.excluded:
                continue
            conn = net_event.conn
            if self.db_audit_source is not None:
                shim_path = getattr(self.db_audit_source, "sqlite_path", "")
                if shim_path and shim_path in (conn.local, conn.remote):
                    continue
            if net_event.initial and not self.show_initial and net_event.kind == "net_open":
                # Still tracked for the current-connections view; suppress the
                # startup burst in the event stream.
                continue
            events.append(
                self._event(
                    net_event.kind,
                    proc,
                    fd=conn.fd if conn.fd >= 0 else None,
                    service=conn.service,
                    net=conn.to_dict(),
                    detail=conn.display(),
                )
            )

    def _scan_db_audit(self, events: List[Event]) -> None:
        if self.db_audit_source is None or not self.db_audit_source.enabled:
            return
        records, errors = self.db_audit_source.poll()
        for message in errors:
            self._warn("db-audit-%s" % message, message, events)
        for record in records:
            pid = record.agent_pid
            if pid is None and self.network_monitor is not None:
                pid = self.network_monitor.find_client_pid(
                    record.client_host, record.client_port
                )
            proc = self.processes.get(pid) if pid is not None else None
            db = record.to_dict()
            if pid is not None:
                db["agent_pid"] = pid
            event = Event(
                ts=record.ts,
                kind="db_query",
                pid=pid or 0,
                name=proc.name if proc is not None else "database",
                ppid=proc.ppid if proc is not None else 0,
                service=record.system,
                reason=record.reason,
                severity=record.risk,
                detail=record.sql,
                db=db,
                via="db_audit",
            )
            if record.risk == "high":
                self.stats.alerts += 1
            events.append(event)

    # ------------------------------------------------------------------ alerts
    def _check_proc_access(
        self, proc: ProcessInfo, fd: int, info: FdInfo, events: List[Event]
    ) -> None:
        victim: Optional[int] = None
        via = ""
        match = PROC_PATH_RE.match(info.path)
        if match:
            candidate = int(match.group(1))
            if candidate in self.policy_match.protected and candidate != proc.pid:
                victim = candidate
                via = "procfs"
        if victim is None and info.target_pid is not None:
            candidate = info.target_pid
            if candidate in self.policy_match.protected and candidate != proc.pid:
                victim = candidate
                via = "pidfd"
        if victim is None:
            return
        key = (proc.pid, fd)
        previous = self._protected_alerts.get(key)
        current = (victim, via)
        if previous == current:
            return
        self._protected_alerts[key] = current
        self.stats.alerts += 1
        events.append(
            self._event(
                "alert",
                proc,
                fd=fd,
                info=info,
                victim_pid=victim,
                victim_name=self._victim_name(victim),
                via=via,
                detail="访问受保护进程",
            )
        )

    def _check_ptrace(self, events: List[Event]) -> None:
        checker = getattr(self.collector, "ptrace_tracer", None)
        if checker is None or not self.policy_match.protected:
            return
        monitored = {
            pid for pid, p in self.processes.items() if not p.excluded and not p.protected
        }
        current: Set[Tuple[int, int]] = set()
        now = time.time()
        for victim in list(self.policy_match.protected):
            if victim == self.root_pid:
                continue
            cached = self._ptrace_cache.get(victim)
            if cached and now - cached[0] < 1.0:
                tracer = cached[1]
            else:
                try:
                    tracer = checker(victim)
                except Exception:
                    tracer = None
                self._ptrace_cache[victim] = (now, tracer)
            if tracer and tracer in monitored and tracer != victim:
                pair = (tracer, victim)
                current.add(pair)
                if pair not in self._ptrace_seen:
                    proc = self.processes.get(tracer) or ProcessInfo(pid=tracer)
                    self.stats.alerts += 1
                    events.append(
                        self._event(
                            "alert",
                            proc,
                            victim_pid=victim,
                            victim_name=self._victim_name(victim),
                            via="ptrace",
                            detail="ptrace 附加到受保护进程",
                        )
                    )
        self._ptrace_seen = current

    def _victim_name(self, pid: int) -> str:
        proc = self.policy_match.protected.get(pid)
        if proc and proc.name:
            return proc.name
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return ""

    def _handle_target_gone(self, events: List[Event]) -> None:
        if self.target_gone:
            return
        self.target_gone = True
        root = self.processes.get(self.root_pid)
        if root is None:
            root = ProcessInfo(pid=self.root_pid, name="", create_time=self._root_create_time or 0.0)
        events.append(self._event("process_exit", root, detail="目标进程已退出"))
        self._warn(
            "target-gone",
            "目标进程 %d 已退出，停止监控" % self.root_pid,
            events,
        )

    # ---------------------------------------------------------------- helpers
    def _event(
        self,
        kind: str,
        proc: ProcessInfo,
        fd: Optional[int] = None,
        info: Optional[FdInfo] = None,
        old: Optional[FdInfo] = None,
        victim_pid: Optional[int] = None,
        victim_name: str = "",
        via: str = "",
        detail: str = "",
        initial: bool = False,
        reason: str = "",
        severity: str = "",
        service: str = "",
        net: Optional[Dict[str, object]] = None,
    ) -> Event:
        if info is not None:
            path = info.path
            mode = info.mode
            file_kind = info.kind
        elif old is not None:
            path = old.path
            mode = old.mode
            file_kind = old.kind
        else:
            path = ""
            mode = ""
            file_kind = ""
        if old is not None and info is not None:
            detail = detail or ("%s -> %s" % (old.path, info.path))
        return Event(
            ts=time.time(),
            kind=kind,
            pid=proc.pid,
            name=proc.name,
            ppid=proc.ppid,
            fd=fd,
            path=path,
            mode=mode,
            file_kind=file_kind,
            initial=initial,
            reason=reason,
            severity=severity,
            service=service,
            net=net,
            victim_pid=victim_pid,
            victim_name=victim_name,
            via=via,
            detail=detail,
        )

    def _warn(self, code: str, message: str, events: List[Event]) -> None:
        if code in self._warned:
            return
        self._warned.add(code)
        events.append(
            Event(
                ts=time.time(),
                kind="warn",
                pid=0,
                name="proctrace",
                detail=message,
            )
        )

    def _finish_scan(self, started: float) -> None:
        elapsed = time.perf_counter() - started
        self.stats.last_scan_seconds = elapsed
        self.stats.scan_seconds += elapsed
        self.stats.max_scan_seconds = max(self.stats.max_scan_seconds, elapsed)

    def policy_summary(self) -> str:
        return self.policy.describe()
