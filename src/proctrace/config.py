"""JSON configuration handling (no third-party TOML/YAML dependency)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .policy import ConfigError, Rule

TOP_LEVEL_KEYS = {
    "interval",
    "max_events",
    "show_initial",
    "show_nonfile",
    "policy_refresh",
    "tree_refresh",
    "max_processes",
    "protected",
    "exclude",
    "audit",
    "network",
    "database",
    "kernel",
    "db_audit",
}
ALLOWED_META_KEYS = {"$schema", "_comment"}
NETWORK_KEYS = {"enabled", "include_unix", "db_ports", "ignore_ports"}
DATABASE_KEYS = {"enabled", "sqlite_suffixes"}
KERNEL_KEYS = {"enabled", "mark_paths", "include_writes"}
DB_AUDIT_KEYS = {"enabled", "from_start", "sources", "sensitive_tables"}
DB_AUDIT_SOURCE_KEYS = {"system", "path", "format"}

AUDIT_KEYS = {
    "enabled",
    "workspaces",
    "allow_paths",
    "deny_paths",
    "ignore_paths",
    "outside_workspace",
    "use_defaults",
    "include_stdio",
}

DEFAULT_INTERVAL = 0.5
DEFAULT_MAX_EVENTS = 5000
DEFAULT_POLICY_REFRESH = 2.0
DEFAULT_TREE_REFRESH = 1.0
DEFAULT_MAX_PROCESSES = 2048


def default_config() -> Dict[str, Any]:
    return {
        "interval": DEFAULT_INTERVAL,
        "max_events": DEFAULT_MAX_EVENTS,
        "show_initial": False,
        "show_nonfile": False,
        "policy_refresh": DEFAULT_POLICY_REFRESH,
        "tree_refresh": DEFAULT_TREE_REFRESH,
        "max_processes": DEFAULT_MAX_PROCESSES,
        "protected": [],
        "exclude": [],
        "audit": {
            "enabled": False,
            "workspaces": [],
            "allow_paths": [],
            "deny_paths": [],
            "ignore_paths": [],
            "outside_workspace": True,
            "use_defaults": True,
            "include_stdio": False,
        },
        "network": {
            "enabled": False,
            "include_unix": True,
            "db_ports": {},
            "ignore_ports": [],
        },
        "database": {
            "enabled": False,
            "sqlite_suffixes": [".db", ".sqlite", ".sqlite3", ".duckdb", ".mdb", ".accdb"],
        },
        "kernel": {
            "enabled": False,
            "mark_paths": ["/"],
            "include_writes": True,
        },
        "db_audit": {
            "enabled": False,
            "from_start": False,
            "sources": [],
            "sensitive_tables": [
                "users", "credentials", "tokens", "secrets",
                "audit_log", "payment_cards",
            ],
        },
    }


EXAMPLE_CONFIG: Dict[str, Any] = {
    "_comment": "Rules are AND-ed. name/exe use glob, cmdline uses Python regex.",
    "interval": 0.5,
    "max_events": 5000,
    "show_initial": False,
    "show_nonfile": False,
    "policy_refresh": 2.0,
    "tree_refresh": 1.0,
    "max_processes": 2048,
    "protected": [
        {"pid": 1234},
        {"name": "1Password"},
        {"name": "ssh-agent"},
    ],
    "exclude": [
        {"name": "WindowServer"},
        {"name": "kernel_task"},
    ],
    "audit": {
        "enabled": False,
        "workspaces": [],
        "allow_paths": [],
        "deny_paths": [],
        "ignore_paths": [],
        "outside_workspace": True,
        "use_defaults": True,
        "include_stdio": False,
    },
    "network": {
        "enabled": False,
        "include_unix": True,
        "db_ports": {},
        "ignore_ports": [],
    },
    "database": {
        "enabled": False,
        "sqlite_suffixes": [".db", ".sqlite", ".sqlite3", ".duckdb", ".mdb", ".accdb"],
    },
    "kernel": {
        "enabled": False,
        "mark_paths": ["/"],
        "include_writes": True,
    },
    "db_audit": {
        "enabled": False,
        "from_start": False,
        "sources": [],
        "sensitive_tables": [
            "users", "credentials", "tokens", "secrets",
            "audit_log", "payment_cards",
        ],
    },
}


def _number(data: Dict[str, Any], key: str, minimum: float, maximum: float) -> float:
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError("%s 必须是数字" % key)
    value = float(value)
    if not (minimum <= value <= maximum):
        raise ConfigError("%s 必须在 %s 到 %s 之间" % (key, minimum, maximum))
    return value


def _integer(data: Dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("%s 必须是整数" % key)
    if not (minimum <= value <= maximum):
        raise ConfigError("%s 必须在 %d 到 %d 之间" % (key, minimum, maximum))
    return value


def _bool(data: Dict[str, Any], key: str) -> bool:
    value = data[key]
    if not isinstance(value, bool):
        raise ConfigError("%s 必须是布尔值" % key)
    return value


@dataclass
class AuditConfig:
    enabled: bool = False
    workspaces: List[str] = field(default_factory=list)
    allow_paths: List[str] = field(default_factory=list)
    deny_paths: List[str] = field(default_factory=list)
    ignore_paths: List[str] = field(default_factory=list)
    outside_workspace: bool = True
    use_defaults: bool = True
    include_stdio: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "audit") -> "AuditConfig":
        if not isinstance(data, dict):
            raise ConfigError("%s 必须是对象" % where)
        unknown = set(data) - AUDIT_KEYS
        if unknown:
            raise ConfigError("%s 含未知字段: %s" % (where, ", ".join(sorted(unknown))))
        cfg = cls()
        for key in ("enabled", "outside_workspace", "use_defaults", "include_stdio"):
            if key in data:
                if not isinstance(data[key], bool):
                    raise ConfigError("%s.%s 必须是布尔值" % (where, key))
                setattr(cfg, key, data[key])
        for key in ("workspaces", "allow_paths", "deny_paths", "ignore_paths"):
            if key not in data:
                continue
            value = data[key]
            if not isinstance(value, list):
                raise ConfigError("%s.%s 必须是数组" % (where, key))
            items = []
            for index, item in enumerate(value):
                if not isinstance(item, str) or not item:
                    raise ConfigError("%s.%s[%d] 必须是非空字符串" % (where, key, index))
                items.append(item)
            setattr(cfg, key, items)
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "workspaces": list(self.workspaces),
            "allow_paths": list(self.allow_paths),
            "deny_paths": list(self.deny_paths),
            "ignore_paths": list(self.ignore_paths),
            "outside_workspace": self.outside_workspace,
            "use_defaults": self.use_defaults,
            "include_stdio": self.include_stdio,
        }


@dataclass
class NetworkConfig:
    enabled: bool = False
    include_unix: bool = True
    db_ports: Dict[int, str] = field(default_factory=dict)
    ignore_ports: List[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Any, where: str = "network") -> "NetworkConfig":
        if not isinstance(data, dict):
            raise ConfigError("%s 必须是对象" % where)
        unknown = set(data) - NETWORK_KEYS
        if unknown:
            raise ConfigError("%s 含未知字段: %s" % (where, ", ".join(sorted(unknown))))
        cfg = cls()
        for key in ("enabled", "include_unix"):
            if key in data:
                if not isinstance(data[key], bool):
                    raise ConfigError("%s.%s 必须是布尔值" % (where, key))
                setattr(cfg, key, data[key])
        raw_ports = data.get("db_ports", {})
        if not isinstance(raw_ports, dict):
            raise ConfigError("%s.db_ports 必须是对象" % where)
        for key, value in raw_ports.items():
            try:
                port = int(key)
            except (TypeError, ValueError):
                raise ConfigError("%s.db_ports 的键必须是端口号" % where)
            if not (1 <= port <= 65535):
                raise ConfigError("%s.db_ports 端口超出范围: %s" % (where, port))
            if not isinstance(value, str) or not value:
                raise ConfigError("%s.db_ports[%s] 必须是非空服务名" % (where, key))
            cfg.db_ports[port] = value
        raw_ignore = data.get("ignore_ports", [])
        if not isinstance(raw_ignore, list):
            raise ConfigError("%s.ignore_ports 必须是数组" % where)
        for item in raw_ignore:
            if isinstance(item, bool) or not isinstance(item, int) or not (1 <= item <= 65535):
                raise ConfigError("%s.ignore_ports 必须是端口号数组" % where)
            cfg.ignore_ports.append(item)
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "include_unix": self.include_unix,
            "db_ports": {str(k): v for k, v in sorted(self.db_ports.items())},
            "ignore_ports": list(self.ignore_ports),
        }


@dataclass
class DatabaseConfig:
    enabled: bool = False
    sqlite_suffixes: List[str] = field(
        default_factory=lambda: [".db", ".sqlite", ".sqlite3", ".duckdb", ".mdb", ".accdb"]
    )

    @classmethod
    def from_dict(cls, data: Any, where: str = "database") -> "DatabaseConfig":
        if not isinstance(data, dict):
            raise ConfigError("%s 必须是对象" % where)
        unknown = set(data) - DATABASE_KEYS
        if unknown:
            raise ConfigError("%s 含未知字段: %s" % (where, ", ".join(sorted(unknown))))
        cfg = cls()
        if "enabled" in data:
            if not isinstance(data["enabled"], bool):
                raise ConfigError("%s.enabled 必须是布尔值" % where)
            cfg.enabled = data["enabled"]
        if "sqlite_suffixes" in data:
            value = data["sqlite_suffixes"]
            if not isinstance(value, list):
                raise ConfigError("%s.sqlite_suffixes 必须是数组" % where)
            suffixes = []
            for item in value:
                if not isinstance(item, str) or not item:
                    raise ConfigError("%s.sqlite_suffixes 必须是非空字符串数组" % where)
                suffixes.append(item if item.startswith(".") else "." + item)
            cfg.sqlite_suffixes = suffixes
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "sqlite_suffixes": list(self.sqlite_suffixes),
        }


@dataclass
class KernelConfig:
    enabled: bool = False
    mark_paths: List[str] = field(default_factory=lambda: ["/"])
    include_writes: bool = True

    @classmethod
    def from_dict(cls, data: Any, where: str = "kernel") -> "KernelConfig":
        if not isinstance(data, dict):
            raise ConfigError("%s 必须是对象" % where)
        unknown = set(data) - KERNEL_KEYS
        if unknown:
            raise ConfigError("%s 含未知字段: %s" % (where, ", ".join(sorted(unknown))))
        cfg = cls()
        if "enabled" in data:
            if not isinstance(data["enabled"], bool):
                raise ConfigError("%s.enabled 必须是布尔值" % where)
            cfg.enabled = data["enabled"]
        if "include_writes" in data:
            if not isinstance(data["include_writes"], bool):
                raise ConfigError("%s.include_writes 必须是布尔值" % where)
            cfg.include_writes = data["include_writes"]
        if "mark_paths" in data:
            value = data["mark_paths"]
            if not isinstance(value, list):
                raise ConfigError("%s.mark_paths 必须是数组" % where)
            paths = []
            for item in value:
                if not isinstance(item, str) or not item:
                    raise ConfigError("%s.mark_paths 必须是非空字符串数组" % where)
                paths.append(item)
            cfg.mark_paths = paths
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mark_paths": list(self.mark_paths),
            "include_writes": self.include_writes,
        }


@dataclass
class DbAuditSourceConfig:
    system: str
    path: str
    format: str = "auto"

    def to_dict(self) -> Dict[str, Any]:
        return {"system": self.system, "path": self.path, "format": self.format}


@dataclass
class DbAuditConfig:
    enabled: bool = False
    from_start: bool = False
    sources: List[DbAuditSourceConfig] = field(default_factory=list)
    sensitive_tables: List[str] = field(
        default_factory=lambda: [
            "users", "credentials", "tokens", "secrets",
            "audit_log", "payment_cards",
        ]
    )

    @classmethod
    def from_dict(cls, data: Any, where: str = "db_audit") -> "DbAuditConfig":
        if not isinstance(data, dict):
            raise ConfigError("%s 必须是对象" % where)
        unknown = set(data) - DB_AUDIT_KEYS
        if unknown:
            raise ConfigError("%s 含未知字段: %s" % (where, ", ".join(sorted(unknown))))
        cfg = cls()
        for key in ("enabled", "from_start"):
            if key in data:
                if not isinstance(data[key], bool):
                    raise ConfigError("%s.%s 必须是布尔值" % (where, key))
                setattr(cfg, key, data[key])
        if "sensitive_tables" in data:
            value = data["sensitive_tables"]
            if not isinstance(value, list):
                raise ConfigError("%s.sensitive_tables 必须是数组" % where)
            tables = []
            for item in value:
                if not isinstance(item, str) or not item:
                    raise ConfigError("%s.sensitive_tables 必须是非空字符串数组" % where)
                tables.append(item.lower())
            cfg.sensitive_tables = tables
        if "sources" in data:
            value = data["sources"]
            if not isinstance(value, list):
                raise ConfigError("%s.sources 必须是数组" % where)
            sources = []
            for index, item in enumerate(value):
                if not isinstance(item, dict):
                    raise ConfigError("%s.sources[%d] 必须是对象" % (where, index))
                unknown_source = set(item) - DB_AUDIT_SOURCE_KEYS
                if unknown_source:
                    raise ConfigError(
                        "%s.sources[%d] 含未知字段: %s"
                        % (where, index, ", ".join(sorted(unknown_source)))
                    )
                system = str(item.get("system", "")).lower()
                if system in ("postgres", "postgresql"):
                    system = "postgresql"
                if system in ("mysql", "mariadb"):
                    system = "mysql"
                if system not in ("postgresql", "mysql", "sqlite"):
                    raise ConfigError("%s.sources[%d].system 不支持: %s" % (where, index, system))
                path = item.get("path")
                if not isinstance(path, str) or not path:
                    raise ConfigError("%s.sources[%d].path 必须是非空字符串" % (where, index))
                fmt = str(item.get("format", "auto"))
                sources.append(DbAuditSourceConfig(system=system, path=path, format=fmt))
            cfg.sources = sources
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "from_start": self.from_start,
            "sources": [s.to_dict() for s in self.sources],
            "sensitive_tables": list(self.sensitive_tables),
        }


@dataclass
class Config:
    interval: float = DEFAULT_INTERVAL
    max_events: int = DEFAULT_MAX_EVENTS
    show_initial: bool = False
    show_nonfile: bool = False
    policy_refresh: float = DEFAULT_POLICY_REFRESH
    tree_refresh: float = DEFAULT_TREE_REFRESH
    max_processes: int = DEFAULT_MAX_PROCESSES
    protected: List[Rule] = field(default_factory=list)
    exclude: List[Rule] = field(default_factory=list)
    audit: AuditConfig = field(default_factory=AuditConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    kernel: KernelConfig = field(default_factory=KernelConfig)
    db_audit: DbAuditConfig = field(default_factory=DbAuditConfig)
    source: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: Optional[str] = None) -> "Config":
        if not isinstance(data, dict):
            raise ConfigError("配置文件顶层必须是 JSON 对象")
        unknown = set(data) - TOP_LEVEL_KEYS - ALLOWED_META_KEYS
        if unknown:
            raise ConfigError("配置含未知字段: %s" % ", ".join(sorted(unknown)))
        merged = default_config()
        merged.update({k: v for k, v in data.items() if k in TOP_LEVEL_KEYS})

        cfg = cls(source=source)
        cfg.interval = _number(merged, "interval", 0.05, 60.0)
        cfg.max_events = _integer(merged, "max_events", 100, 1_000_000)
        cfg.show_initial = _bool(merged, "show_initial")
        cfg.show_nonfile = _bool(merged, "show_nonfile")
        cfg.policy_refresh = _number(merged, "policy_refresh", 0.5, 300.0)
        cfg.tree_refresh = _number(merged, "tree_refresh", 0.2, 60.0)
        cfg.max_processes = _integer(merged, "max_processes", 16, 100_000)
        for key, target in (("protected", "protected"), ("exclude", "exclude")):
            raw = merged[key]
            if not isinstance(raw, list):
                raise ConfigError("%s 必须是数组" % key)
            rules = []
            for index, item in enumerate(raw):
                rules.append(Rule.from_dict(item, "%s[%d]" % (key, index)))
            setattr(cfg, target, rules)
        audit_data = merged.get("audit", default_config()["audit"])
        cfg.audit = AuditConfig.from_dict(audit_data)
        cfg.network = NetworkConfig.from_dict(merged.get("network", default_config()["network"]))
        cfg.database = DatabaseConfig.from_dict(merged.get("database", default_config()["database"]))
        cfg.kernel = KernelConfig.from_dict(merged.get("kernel", default_config()["kernel"]))
        cfg.db_audit = DbAuditConfig.from_dict(
            merged.get("db_audit", default_config()["db_audit"])
        )
        return cfg

    def copy(self) -> "Config":
        return Config(
            interval=self.interval,
            max_events=self.max_events,
            show_initial=self.show_initial,
            show_nonfile=self.show_nonfile,
            policy_refresh=self.policy_refresh,
            tree_refresh=self.tree_refresh,
            max_processes=self.max_processes,
            protected=list(self.protected),
            exclude=list(self.exclude),
            audit=AuditConfig(
                enabled=self.audit.enabled,
                workspaces=list(self.audit.workspaces),
                allow_paths=list(self.audit.allow_paths),
                deny_paths=list(self.audit.deny_paths),
                ignore_paths=list(self.audit.ignore_paths),
                outside_workspace=self.audit.outside_workspace,
                use_defaults=self.audit.use_defaults,
                include_stdio=self.audit.include_stdio,
            ),
            network=NetworkConfig(
                enabled=self.network.enabled,
                include_unix=self.network.include_unix,
                db_ports=dict(self.network.db_ports),
                ignore_ports=list(self.network.ignore_ports),
            ),
            database=DatabaseConfig(
                enabled=self.database.enabled,
                sqlite_suffixes=list(self.database.sqlite_suffixes),
            ),
            kernel=KernelConfig(
                enabled=self.kernel.enabled,
                mark_paths=list(self.kernel.mark_paths),
                include_writes=self.kernel.include_writes,
            ),
            db_audit=DbAuditConfig(
                enabled=self.db_audit.enabled,
                from_start=self.db_audit.from_start,
                sources=[DbAuditSourceConfig(s.system, s.path, s.format) for s in self.db_audit.sources],
                sensitive_tables=list(self.db_audit.sensitive_tables),
            ),
            source=self.source,
            warnings=list(self.warnings),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interval": self.interval,
            "max_events": self.max_events,
            "show_initial": self.show_initial,
            "show_nonfile": self.show_nonfile,
            "policy_refresh": self.policy_refresh,
            "tree_refresh": self.tree_refresh,
            "max_processes": self.max_processes,
            "protected": [rule.to_dict() for rule in self.protected],
            "exclude": [rule.to_dict() for rule in self.exclude],
            "audit": self.audit.to_dict(),
            "network": self.network.to_dict(),
            "database": self.database.to_dict(),
            "kernel": self.kernel.to_dict(),
            "db_audit": self.db_audit.to_dict(),
        }

    def add_protected_rule(self, rule: Rule) -> None:
        self.protected.append(rule)

    def add_exclude_rule(self, rule: Rule) -> None:
        self.exclude.append(rule)


def config_search_paths() -> List[str]:
    paths = []
    env = os.environ.get("PROCTRACE_CONFIG")
    if env:
        paths.append(os.path.expanduser(env))
    paths.append(os.path.join(os.getcwd(), "proctrace.json"))
    paths.append(os.path.expanduser("~/.config/proctrace/config.json"))
    return paths


def find_config(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    for path in config_search_paths():
        if os.path.isfile(path):
            return path
    return None


def load_config(path: Optional[str] = None, required: bool = False) -> Config:
    resolved = find_config(path)
    if resolved is None:
        if required or path:
            raise ConfigError("找不到配置文件: %s" % (path or "proctrace.json"))
        return Config()
    try:
        with open(resolved, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise ConfigError("读取配置失败 %s: %s" % (resolved, exc))
    except json.JSONDecodeError as exc:
        raise ConfigError("JSON 解析失败 %s:%d: %s" % (resolved, exc.lineno, exc.msg))
    return Config.from_dict(data, source=resolved)


def write_example(path: str, force: bool = False) -> None:
    if os.path.exists(path) and not force:
        raise ConfigError("文件已存在: %s (使用 --force 覆盖)" % path)
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(EXAMPLE_CONFIG, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
