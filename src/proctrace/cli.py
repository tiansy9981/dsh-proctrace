"""Command line interface."""

from __future__ import annotations

import argparse
import math
import os
import signal
import subprocess
import sys
import time
from typing import List, Optional, Sequence, TextIO

from . import __version__
from .collector import BackendUnavailable, make_collector
from .config import Config, ConfigError, find_config, load_config, write_example
from .config import DbAuditSourceConfig
from .db_audit import DbAuditSource, find_sqlite_shim
from .engine import Monitor, TargetGone, TargetRejected
from .kernel import KernelUnavailable, make_kernel_source
from .pathpolicy import DEFAULT_ALLOW_PATTERNS, DEFAULT_DENY_PATTERNS, PathAudit
from .policy import Policy, Rule
from .render import (
    human_snapshot,
    is_visible_event,
    snapshot_json,
    write_event,
    write_jsonl_event,
)
from .target import Target, TargetError, resolve_target
from .tui import TUI
from .utils import sanitize


def eprint(*args, **kwargs) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("目标选择（三选一）")
    group.add_argument("--pid", type=int, help="按 PID 监控")
    group.add_argument("--name", help="按进程名 glob 监控，多个匹配时选最新启动的")
    group.add_argument("--cmdline", help="按命令行正则监控，多个匹配时选最新启动的")


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("配置")
    group.add_argument("--config", help="JSON 配置文件路径")
    group.add_argument("--no-config", action="store_true", help="不读取任何配置文件")
    group.add_argument("--protect", type=int, action="append", default=[], metavar="PID",
                       help="追加受保护进程 PID（可重复）")
    group.add_argument("--protect-name", action="append", default=[], metavar="GLOB",
                       help="追加受保护进程名 glob（可重复）")
    group.add_argument("--exclude-pid", type=int, action="append", default=[], metavar="PID",
                       help="追加排除进程 PID（可重复）")
    group.add_argument("--exclude-name", action="append", default=[], metavar="GLOB",
                       help="追加排除进程名 glob（可重复）")


def _add_audit_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("文件路径审计（AI agent 场景）")
    group.add_argument("--audit", action="store_true", help="启用工作区/敏感路径审计")
    group.add_argument("--workspace", action="append", default=[], metavar="PATH",
                       help="授权工作区，可重复；默认使用目标进程 cwd")
    group.add_argument("--allow-path", action="append", default=[], metavar="GLOB",
                       help="额外允许的路径 glob（可重复）")
    group.add_argument("--deny-path", action="append", default=[], metavar="GLOB",
                       help="额外敏感/禁止路径 glob（可重复）")
    group.add_argument("--ignore-path", action="append", default=[], metavar="GLOB",
                       help="完全忽略的路径 glob（可重复）")
    group.add_argument("--no-default-audit-paths", action="store_true",
                       help="不使用内置的系统放行/敏感路径规则")
    group.add_argument("--no-outside-workspace", action="store_true",
                       help="只检查 deny 规则，不报告工作区外访问")
    group.add_argument("--audit-stdio", action="store_true",
                       help="也审计 stdin/stdout/stderr（默认忽略 fd 0/1/2）")
    group.add_argument("--network", action="store_true",
                       help="监控目标进程树的网络连接（元数据）")
    group.add_argument("--database", action="store_true",
                       help="监控 SQLite 文件访问与数据库端口连接")
    group.add_argument("--no-network-unix", action="store_true",
                       help="不显示 Unix domain socket 连接")
    group.add_argument("--db-port", action="append", default=[], metavar="PORT:SERVICE",
                       help="追加数据库端口映射，例如 5432:postgresql")
    group.add_argument("--kernel", action="store_true",
                       help="启用内核事件流（macOS eslogger / Linux fanotify；需要 root）")
    group.add_argument("--kernel-mark", action="append", default=[], metavar="PATH",
                       help="fanotify 标记路径，可重复，默认 /")
    group.add_argument("--no-kernel-writes", action="store_true",
                       help="不采集内核 write 事件（仍采集 open/read/close）")
    group.add_argument("--db-audit", action="append", default=[], metavar="SYSTEM:PATH",
                       help="读取数据库审计日志，如 postgres:/var/log/pg.log；可重复")
    group.add_argument("--db-audit-from-start", action="store_true",
                       help="从审计日志开头读取（默认只读新行）")


def _add_runtime_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("运行参数")
    group.add_argument("--backend", choices=("auto", "procfs", "psutil"), default="auto",
                       help="采集后端；Linux 默认 procfs，macOS 默认 psutil/libproc")
    group.add_argument("--interval", type=float, help="轮询间隔秒数，默认 0.5")
    group.add_argument("--no-children", action="store_true", help="只监控目标本身，不包含子进程")
    group.add_argument("--max-events", type=int, help="TUI 保留的事件条数，默认 5000")
    group.add_argument("--max-processes", type=int, help="进程树上限，默认 2048")
    group.add_argument("--policy-refresh", type=float, help="保护/排除规则的重新匹配间隔，默认 2s")
    group.add_argument("--tree-refresh", type=float, help="重新发现子进程的间隔，默认 1s")
    group.add_argument("--all-types", action="store_true", help="显示 socket/pipe/anon 等非普通文件")
    group.add_argument("--show-initial", action="store_true", help="启动时输出已打开文件的基线")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proctrace",
        description="实时查看进程及其子进程打开了哪些文件，并对访问受保护进程的行为告警。",
    )
    parser.add_argument("--version", action="version", version="proctrace " + __version__)
    sub = parser.add_subparsers(dest="command")

    watch = sub.add_parser("watch", help="实时监控（默认 TUI；非 TTY 自动逐行输出）")
    _add_target_args(watch)
    _add_config_args(watch)
    _add_audit_args(watch)
    _add_runtime_args(watch)
    watch.add_argument("--json", action="store_true", help="输出 JSONL 事件（隐含 --no-tui）")
    watch.add_argument("--no-tui", action="store_true", help="不使用全屏 TUI，逐行输出")
    watch.add_argument("--log", metavar="FILE", help="同时把事件写入 JSONL 文件")
    watch.add_argument("--duration", type=float, metavar="SECONDS", help="运行指定秒数后退出")
    watch.add_argument("--quiet", action="store_true", help="不输出启动/结束摘要")
    watch.add_argument("--log-only", action="store_true", help="事件只写 --log，不写 stdout")

    runp = sub.add_parser("run", help="启动命令并监控它（SQLite shim 需要此模式）")
    _add_config_args(runp)
    _add_audit_args(runp)
    _add_runtime_args(runp)
    runp.add_argument("--json", action="store_true", help="输出 JSONL 事件")
    runp.add_argument("--no-tui", action="store_true", help="不进入全屏 TUI")
    runp.add_argument("--log", metavar="FILE", help="事件 JSONL 日志")
    runp.add_argument("--duration", type=float, metavar="SECONDS", help="运行指定秒数后退出")
    runp.add_argument("--quiet", action="store_true", help="不输出启动/结束摘要")
    runp.add_argument("--log-only", action="store_true", help="事件只写 --log，不写 stdout")
    runp.add_argument("--child-log", metavar="FILE", help="把子进程 stdout/stderr 写入文件")
    runp.add_argument("--keep-child", action="store_true", help="监控退出时保留子进程")
    runp.add_argument("--cwd", metavar="DIR", help="子进程工作目录，默认当前目录")
    runp.add_argument("cmd", nargs=argparse.REMAINDER, help="-- 后面的命令")

    snap = sub.add_parser("snapshot", help="抓取一次当前进程树和打开的文件")
    _add_target_args(snap)
    _add_config_args(snap)
    _add_audit_args(snap)
    _add_runtime_args(snap)
    snap.add_argument("--json", action="store_true", help="输出 JSON")

    sub.add_parser("doctor", help="检查平台、权限、后端和依赖")

    init = sub.add_parser("init", help="生成示例配置文件")
    init.add_argument("--path", default="proctrace.json", help="写入路径，默认 ./proctrace.json")
    init.add_argument("--force", action="store_true", help="覆盖已存在的文件")

    return parser


def _check_range(name: str, value: float, low: float, high: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError("%s 必须是数字" % name)
    if not math.isfinite(float(value)) or not (low <= value <= high):
        raise ConfigError("%s 必须在 %s 到 %s 之间" % (name, low, high))


def build_config(args: argparse.Namespace) -> Config:
    if args.no_config and args.config:
        raise ConfigError("--config 和 --no-config 不能同时使用")
    if args.no_config:
        cfg = Config()
    else:
        cfg = load_config(args.config, required=bool(args.config))

    if args.interval is not None:
        _check_range("--interval", args.interval, 0.05, 60.0)
        cfg.interval = float(args.interval)
    if args.max_events is not None:
        _check_range("--max-events", args.max_events, 100, 1_000_000)
        cfg.max_events = int(args.max_events)
    if args.max_processes is not None:
        _check_range("--max-processes", args.max_processes, 16, 100_000)
        cfg.max_processes = int(args.max_processes)
    if args.policy_refresh is not None:
        _check_range("--policy-refresh", args.policy_refresh, 0.5, 300.0)
        cfg.policy_refresh = float(args.policy_refresh)
    if args.tree_refresh is not None:
        _check_range("--tree-refresh", args.tree_refresh, 0.2, 60.0)
        cfg.tree_refresh = float(args.tree_refresh)
    if getattr(args, "duration", None) is not None:
        _check_range("--duration", args.duration, 0.01, 86400.0)
    if args.all_types:
        cfg.show_nonfile = True
    if args.show_initial:
        cfg.show_initial = True

    if args.audit:
        cfg.audit.enabled = True
    if args.workspace:
        cfg.audit.workspaces.extend(args.workspace)
        cfg.audit.enabled = True
    if args.allow_path:
        cfg.audit.allow_paths.extend(args.allow_path)
        cfg.audit.enabled = True
    if args.deny_path:
        cfg.audit.deny_paths.extend(args.deny_path)
        cfg.audit.enabled = True
    if args.ignore_path:
        cfg.audit.ignore_paths.extend(args.ignore_path)
        cfg.audit.enabled = True
    if args.no_default_audit_paths:
        cfg.audit.use_defaults = False
    if args.no_outside_workspace:
        cfg.audit.outside_workspace = False
    if args.audit_stdio:
        cfg.audit.include_stdio = True
        cfg.audit.enabled = True
    if args.network:
        cfg.network.enabled = True
    if args.database:
        cfg.database.enabled = True
        cfg.network.enabled = True
    if args.kernel:
        cfg.kernel.enabled = True
    if args.kernel_mark:
        cfg.kernel.mark_paths = list(args.kernel_mark)
    if args.no_kernel_writes:
        cfg.kernel.include_writes = False
    if args.db_audit_from_start:
        cfg.db_audit.from_start = True
    for spec in args.db_audit:
        try:
            system, path = spec.split(":", 1)
        except ValueError:
            raise ConfigError("--db-audit 需要 SYSTEM:PATH，例如 postgres:/var/log/pg.log")
        system = system.lower()
        if system in ("postgres", "postgresql"):
            system = "postgresql"
        elif system in ("mysql", "mariadb"):
            system = "mysql"
        elif system not in ("sqlite",):
            raise ConfigError("--db-audit 不支持的系统: %s" % system)
        if not path:
            raise ConfigError("--db-audit 路径不能为空")
        cfg.db_audit.sources.append(DbAuditSourceConfig(system=system, path=path))
        cfg.db_audit.enabled = True
        cfg.network.enabled = True
        cfg.database.enabled = True
    if args.no_network_unix:
        cfg.network.include_unix = False
    for spec in args.db_port:
        try:
            port_text, service = spec.split(":", 1)
            port = int(port_text)
        except (ValueError, AttributeError):
            raise ConfigError("--db-port 需要 PORT:SERVICE，例如 5432:postgresql")
        if not (1 <= port <= 65535) or not service:
            raise ConfigError("--db-port 端口或服务名无效: %s" % spec)
        cfg.network.db_ports[port] = service
        cfg.network.enabled = True

    for pid in args.protect:
        if pid <= 0:
            raise ConfigError("--protect 必须是正整数")
        cfg.protected.append(Rule(pid=pid))
    for pattern in args.protect_name:
        if not pattern:
            raise ConfigError("--protect-name 不能为空")
        cfg.protected.append(Rule(name=pattern))
    for pid in args.exclude_pid:
        if pid <= 0:
            raise ConfigError("--exclude-pid 必须是正整数")
        cfg.exclude.append(Rule(pid=pid))
    for pattern in args.exclude_name:
        if not pattern:
            raise ConfigError("--exclude-name 不能为空")
        cfg.exclude.append(Rule(name=pattern))
    return cfg


def _notes_for(cfg: Config, target: Target, follow_children: bool) -> List[str]:
    notes = list(target.notes)
    if cfg.network.enabled:
        notes.append("network: connection metadata only; no payload/TLS content.")
    if cfg.database.enabled:
        notes.append("database: SQLite file activity + DB endpoints; SQL statements need DB audit logs.")
    if cfg.kernel.enabled:
        notes.append("kernel: event-level file backend; requires root and Full Disk Access on macOS.")
    if cfg.db_audit.sources:
        notes.append(
            "db audit: SQL is redacted before logging; SQLite needs the shim/run mode."
        )
    for warning in cfg.warnings:
        if warning not in notes:
            notes.append(warning)
    if sys.platform == "darwin" and cfg.protected:
        notes.append(
            "macOS: task_for_pid/ptrace not visible without ESF; protected is mark/skip only."
        )
    if sys.platform.startswith("linux") and cfg.protected:
        notes.append("Linux: procfs paths, pidfd and TracerPid are checked best-effort.")
    try:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            notes.append("non-root: other users' processes may be inaccessible.")
    except OSError:
        pass
    if not follow_children:
        notes.append("only the target process is monitored (--no-children).")
    return notes


def _ignore_audit_helpers(cfg: Config, source) -> None:
    if source is None:
        return
    for path in source.ignore_paths():
        if path and path not in cfg.audit.ignore_paths:
            cfg.audit.ignore_paths.append(path)


def _build_audit(cfg: Config, target: Target) -> Optional[PathAudit]:
    if not cfg.audit.enabled:
        return None
    workspaces = cfg.audit.workspaces or [target.cwd or os.getcwd()]
    audit_cfg = cfg.audit
    if not audit_cfg.workspaces:
        # Build a shallow copy so the original config still reports what the
        # user supplied.
        from dataclasses import replace

        audit_cfg = replace(audit_cfg, workspaces=list(workspaces))
    audit = PathAudit(audit_cfg, default_workspace=target.cwd or os.getcwd())
    for warning in audit.warnings:
        cfg.warnings.append(warning)
    return audit


def _build_kernel(cfg: Config):
    if not cfg.kernel.enabled:
        return None
    source = make_kernel_source(
        mark_paths=cfg.kernel.mark_paths,
        include_writes=cfg.kernel.include_writes,
    )
    ok, reason = source.available()
    if not ok:
        raise ConfigError("--kernel: %s" % reason)
    return source


def _build_db_audit(cfg: Config) -> Optional[DbAuditSource]:
    if not cfg.db_audit.enabled or not cfg.db_audit.sources:
        return None
    source = DbAuditSource(cfg.db_audit)
    if not source.enabled:
        raise ConfigError("数据库审计源初始化失败")
    if source.sqlite_path and not find_sqlite_shim():
        cfg.warnings.append(
            "SQLite shim 未构建；运行 scripts/build_shim.sh 才能采集 SQLite SQL。"
        )
    return source


def _make_monitor(
    args: argparse.Namespace,
    cfg: Config,
    target: Target,
    path_audit: Optional[PathAudit] = None,
    kernel_source=None,
    db_audit_source=None,
) -> tuple:
    collector = make_collector(args.backend)
    policy = Policy(cfg.protected, cfg.exclude)
    monitor = Monitor(
        target.pid,
        collector,
        cfg,
        policy=policy,
        follow_children=not args.no_children,
        path_audit=path_audit,
        kernel_source=kernel_source,
        db_audit_source=db_audit_source,
    )
    monitor.preflight()
    return monitor, collector


def _open_log(path: Optional[str]) -> Optional[TextIO]:
    if not path:
        return None
    try:
        return open(path, "w", encoding="utf-8", errors="backslashreplace", buffering=1)
    except OSError as exc:
        raise ConfigError("无法打开日志文件 %s: %s" % (path, exc))


def _header(cfg: Config, target: Target, monitor: Monitor, notes: Sequence[str]) -> None:
    eprint(
        "proctrace %s | target=%d (%s) | backend=%s | interval=%.2fs | children=%s"
        % (
            __version__,
            target.pid,
            sanitize(target.name or "?"),
            monitor.collector.name,
            cfg.interval,
            "on" if monitor.follow_children else "off",
        )
    )
    eprint("capabilities: %s" % ", ".join(monitor.capabilities()))
    if cfg.protected or cfg.exclude:
        eprint("policy: protected=%d exclude=%d" % (len(cfg.protected), len(cfg.exclude)))
    if monitor.path_audit is not None and monitor.path_audit.enabled:
        eprint("audit: %s" % monitor.path_audit.summary())
    if cfg.network.enabled:
        eprint(
            "network: connections=on unix=%s db_ports=%d"
            % ("on" if cfg.network.include_unix else "off", len(cfg.network.db_ports))
        )
    if cfg.database.enabled:
        eprint("database: sqlite files + DB endpoints; SQL-level needs DB audit logs")
    if monitor.kernel_source is not None:
        eprint("kernel: %s" % monitor.kernel_source.name)
    if monitor.db_audit_source is not None:
        eprint("db audit: %s" % ", ".join(s.system + ":" + s.path for s in cfg.db_audit.sources))
    if cfg.source:
        eprint("config: %s" % cfg.source)
    for note in notes:
        eprint("note: %s" % sanitize(note))


def _summary(monitor: Monitor) -> str:
    stats = monitor.stats
    return (
        "stopped: polls=%d events=%d alerts=%d procs=%d fds=%d "
        "scan_avg=%.1fms scan_max=%.1fms"
        % (
            stats.polls,
            stats.events,
            stats.alerts,
            stats.process_count,
            stats.fd_count,
            (stats.scan_seconds / stats.polls * 1000) if stats.polls else 0.0,
            stats.max_scan_seconds * 1000,
        )
    )


def run_plain(
    monitor: Monitor,
    cfg: Config,
    args: argparse.Namespace,
    log_handle: Optional[TextIO],
    notes: Sequence[str],
    target: Target,
) -> int:
    show_nonfile = cfg.show_nonfile
    if not args.quiet:
        _header(cfg, target, monitor, notes)
    stop = {"flag": False}

    def _on_signal(signum, frame):
        stop["flag"] = True

    old_int = signal.signal(signal.SIGINT, _on_signal)
    old_term = signal.signal(signal.SIGTERM, _on_signal)
    started = time.monotonic()
    next_poll = started
    try:
        while not stop["flag"]:
            events = monitor.poll()
            for event in events:
                if log_handle is not None:
                    write_jsonl_event(event, stream=log_handle)
                if not is_visible_event(event, show_nonfile):
                    continue
                if getattr(args, "log_only", False):
                    continue
                if args.json:
                    write_jsonl_event(event)
                else:
                    write_event(event, show_nonfile=show_nonfile)
            if log_handle is not None:
                log_handle.flush()
            sys.stdout.flush()
            if monitor.target_gone:
                # The SQLite shim sends asynchronously; give a short grace
                # period so a very short SQLite command is still recorded.
                if monitor.db_audit_source is not None:
                    time.sleep(0.1)
                    for event in monitor.drain_supplemental():
                        if log_handle is not None:
                            write_jsonl_event(event, stream=log_handle)
                        if is_visible_event(event, show_nonfile) and not getattr(
                            args, "log_only", False
                        ):
                            if args.json:
                                write_jsonl_event(event)
                            else:
                                write_event(event, show_nonfile=show_nonfile)
                    if log_handle is not None:
                        log_handle.flush()
                break
            if args.duration is not None and time.monotonic() - started >= args.duration:
                break
            next_poll = time.monotonic() + cfg.interval
            while not stop["flag"] and time.monotonic() < next_poll:
                time.sleep(min(0.05, max(0.0, next_poll - time.monotonic())))
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
    if not args.quiet:
        eprint(_summary(monitor))
    return 0


def _use_tui(args: argparse.Namespace) -> bool:
    return (
        not args.no_tui
        and not args.json
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and os.environ.get("TERM", "") not in ("", "dumb")
    )


def _run_ui(
    monitor: Monitor,
    cfg: Config,
    args: argparse.Namespace,
    target: Target,
    notes: Sequence[str],
    log_handle: Optional[TextIO],
) -> int:
    use_tui = _use_tui(args)
    if use_tui:
        audit_notes = []
        if monitor.path_audit is not None:
            audit_notes.append(monitor.path_audit.summary())
        tui = TUI(
            monitor,
            target_label="%d %s" % (target.pid, target.name or "?"),
            notes=audit_notes + list(notes),
            show_nonfile=cfg.show_nonfile,
            log_handle=log_handle,
        )
        code = tui.run()
        if code == 2:
            eprint("终端 UI 不可用，切换为逐行模式")
            return run_plain(monitor, cfg, args, log_handle, notes, target)
        if not args.quiet:
            eprint(_summary(monitor))
        return code
    return run_plain(monitor, cfg, args, log_handle, notes, target)


def _terminate_child(proc) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except OSError:
            pass


def run_command(args: argparse.Namespace) -> int:
    cfg = build_config(args)
    command = list(args.cmd)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ConfigError("run 需要一个命令，例如：proctrace run -- -- claude")
    db_source = _build_db_audit(cfg)
    env = dict(os.environ)
    if db_source is not None:
        shim_env = db_source.shim_env()
        lib = shim_env.pop("DYLD_INSERT_LIBRARIES", "")
        lib = shim_env.pop("LD_PRELOAD", "") or lib
        if lib:
            key = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
            existing = env.get(key, "")
            env[key] = lib + (":" + existing if existing else "")
        env.update(shim_env)

    child_log = None
    child_stdout = None
    child_stderr = None
    if args.child_log:
        child_log = open(args.child_log, "a", encoding="utf-8", errors="backslashreplace")
        child_stdout = child_log
        child_stderr = child_log
    elif args.json or _use_tui(args):
        # Keep JSONL/TUI output clean; use --child-log for child output.
        child_stdout = subprocess.DEVNULL
        child_stderr = subprocess.DEVNULL
    proc = None
    try:
        try:
            proc = subprocess.Popen(
                command,
                env=env,
                cwd=args.cwd or None,
                stdout=child_stdout,
                stderr=child_stderr,
            )
        except OSError as exc:
            raise ConfigError("启动命令失败: %s" % exc)
        target = resolve_target(pid=proc.pid)
        _ignore_audit_helpers(cfg, db_source)
        path_audit = _build_audit(cfg, target)
        kernel_source = _build_kernel(cfg)
        monitor, _collector = _make_monitor(
            args, cfg, target, path_audit, kernel_source, db_source
        )
        try:
            monitor.start_kernel()
        except Exception:
            monitor.close()
            raise
        notes = _notes_for(cfg, target, monitor.follow_children)
        log_handle = _open_log(args.log)
        try:
            return _run_ui(monitor, cfg, args, target, notes, log_handle)
        finally:
            if log_handle is not None:
                log_handle.close()
            monitor.close()
    finally:
        if proc is not None and not args.keep_child:
            _terminate_child(proc)
        if db_source is not None:
            db_source.close()
        if child_log is not None:
            child_log.close()


def run_watch(args: argparse.Namespace) -> int:
    cfg = build_config(args)
    target = resolve_target(args.pid, args.name, args.cmdline)
    db_audit_source = _build_db_audit(cfg)
    if db_audit_source is not None and db_audit_source.sqlite_path:
        cfg.warnings.append(
            "SQLite SQL 需要目标以 proctrace run 启动（shim 注入）；"
            "watch 模式下只能看 db_file 文件事件。"
        )
    _ignore_audit_helpers(cfg, db_audit_source)
    path_audit = _build_audit(cfg, target)
    kernel_source = _build_kernel(cfg)
    monitor, _collector = _make_monitor(
        args, cfg, target, path_audit, kernel_source, db_audit_source
    )
    try:
        monitor.start_kernel()
    except Exception:
        monitor.close()
        raise
    notes = _notes_for(cfg, target, monitor.follow_children)
    log_handle = _open_log(args.log)
    try:
        return _run_ui(monitor, cfg, args, target, notes, log_handle)
    finally:
        if log_handle is not None:
            log_handle.close()
        monitor.close()


def run_snapshot(args: argparse.Namespace) -> int:
    cfg = build_config(args)
    target = resolve_target(args.pid, args.name, args.cmdline)
    db_audit_source = _build_db_audit(cfg)
    _ignore_audit_helpers(cfg, db_audit_source)
    path_audit = _build_audit(cfg, target)
    kernel_source = _build_kernel(cfg)
    monitor, _collector = _make_monitor(
        args, cfg, target, path_audit, kernel_source, db_audit_source
    )
    try:
        monitor.start_kernel()
        events = monitor.poll()
        if monitor.target_gone:
            raise TargetError("目标进程 %d 已退出" % target.pid)
        data = monitor.export()
        data["alerts"] = [e.to_dict() for e in events if e.kind == "alert"]
        data["violations"] = [e.to_dict() for e in events if e.kind == "violation"]
        data["database_events"] = [
            e.to_dict() for e in events if e.kind.startswith("db_")
        ]
        notes = _notes_for(cfg, target, monitor.follow_children)
        data["notes"] = notes
        if args.json:
            sys.stdout.write(snapshot_json(data) + "\n")
        else:
            sys.stdout.write(human_snapshot(data, show_nonfile=cfg.show_nonfile) + "\n")
        return 0
    finally:
        monitor.close()


def run_doctor() -> int:
    import platform

    try:
        import psutil
    except ImportError:
        psutil = None
    print("proctrace doctor")
    print("proctrace: %s" % __version__)
    print("platform: %s %s %s" % (platform.system(), platform.release(), platform.machine()))
    print("python: %s (%s)" % (sys.version.split()[0], sys.executable))
    print("psutil: %s" % (getattr(psutil, "__version__", "MISSING")))
    try:
        collector = make_collector("auto")
        print("backend: %s" % collector.name)
        print("capabilities: %s" % ", ".join(collector.capabilities()))
    except BackendUnavailable as exc:
        print("backend: UNAVAILABLE (%s)" % exc)
        return 1
    try:
        euid = os.geteuid()
        print("euid: %d%s" % (euid, " (root)" if euid == 0 else " (non-root)"))
    except AttributeError:
        pass
    print("procfs: %s" % ("yes" if os.path.isdir("/proc/self/fd") else "no"))
    if sys.platform == "darwin":
        print("protected alerts: limited (no procfs; task_for_pid needs ESF; ptrace not visible unprivileged)")
    else:
        print("protected alerts: procfs paths, pidfd, TracerPid (best effort)")
    print(
        "audit defaults: %d allow / %d deny; workspace defaults to target cwd"
        % (len(DEFAULT_ALLOW_PATTERNS), len(DEFAULT_DENY_PATTERNS))
    )
    from .network import DEFAULT_DB_PORTS

    print("network: psutil connection polling; default DB ports=%d" % len(DEFAULT_DB_PORTS))
    try:
        ks = make_kernel_source()
        ok, reason = ks.available()
        print(
            "kernel: %s%s"
            % ("available" if ok else "unavailable", "" if ok else " (%s)" % reason)
        )
    except Exception as exc:
        print("kernel: unavailable (%s)" % exc)
    print(
        "sqlite shim: %s (run scripts/build_shim.sh if missing)"
        % (find_sqlite_shim() or "missing")
    )
    print("db audit: PostgreSQL/MySQL log tail + SQLite shim (SQL redacted)")
    print("config: %s" % (find_config(None) or "(none; using defaults)"))
    print("tui: %s (ANSI/termios) TERM=%s" % ("yes" if _tui_ok() else "no", os.environ.get("TERM", "")))
    print("tty: stdin=%s stdout=%s" % (sys.stdin.isatty(), sys.stdout.isatty()))
    return 0


def _tui_ok() -> bool:
    try:
        import termios  # noqa: F401
        import tty  # noqa: F401
    except ImportError:
        return False
    return True


def run_init(args: argparse.Namespace) -> int:
    try:
        write_example(args.path, force=args.force)
    except ConfigError:
        raise
    print("wrote %s" % os.path.abspath(args.path))
    print("edit protected/exclude rules, then run: proctrace watch --pid <PID> --config %s" % args.path)
    return 0


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        if args.command == "watch":
            return run_watch(args)
        if args.command == "run":
            return run_command(args)
        if args.command == "snapshot":
            return run_snapshot(args)
        if args.command == "doctor":
            return run_doctor()
        if args.command == "init":
            return run_init(args)
        parser.error("unknown command")
    except (
        ConfigError,
        TargetError,
        TargetRejected,
        BackendUnavailable,
        KernelUnavailable,
        TargetGone,
    ) as exc:
        eprint("proctrace: error: %s" % exc)
        return 2
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        return 130
    return 0
