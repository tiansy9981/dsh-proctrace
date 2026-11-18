import json

import pytest

from proctrace.config import Config, ConfigError, EXAMPLE_CONFIG, load_config, write_example


def test_defaults():
    cfg = Config()
    assert cfg.interval == 0.5
    assert cfg.protected == []


def test_parse_rules():
    cfg = Config.from_dict(
        {
            "interval": 1.0,
            "protected": [{"name": "ssh*"}, {"pid": 12}],
            "exclude": [{"name": "WindowServer"}],
        }
    )
    assert cfg.interval == 1.0
    assert len(cfg.protected) == 2
    assert cfg.protected[0].name == "ssh*"
    assert cfg.exclude[0].name == "WindowServer"


def test_example_is_valid():
    cfg = Config.from_dict(EXAMPLE_CONFIG)
    assert cfg.protected
    assert cfg.exclude


def test_unknown_field():
    with pytest.raises(ConfigError):
        Config.from_dict({"interval": 1, "intervall": 2})


def test_bad_types_and_ranges():
    with pytest.raises(ConfigError):
        Config.from_dict({"interval": "fast"})
    with pytest.raises(ConfigError):
        Config.from_dict({"interval": 0})
    with pytest.raises(ConfigError):
        Config.from_dict({"max_events": 3})
    with pytest.raises(ConfigError):
        Config.from_dict({"protected": {"name": "x"}})


def test_load_and_write(tmp_path):
    path = tmp_path / "proctrace.json"
    write_example(str(path))
    assert path.exists()
    cfg = load_config(str(path), required=True)
    assert cfg.source == str(path)
    with pytest.raises(ConfigError):
        write_example(str(path))


def test_load_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(path), required=True)


def test_load_missing_required(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "missing.json"), required=True)


def test_audit_config():
    cfg = Config.from_dict(
        {
            "audit": {
                "enabled": True,
                "workspaces": ["/tmp/project"],
                "deny_paths": ["~/.ssh/**"],
                "outside_workspace": False,
            }
        }
    )
    assert cfg.audit.enabled is True
    assert cfg.audit.workspaces == ["/tmp/project"]
    assert cfg.audit.outside_workspace is False
    assert cfg.audit.to_dict()["use_defaults"] is True


def test_audit_unknown_field():
    with pytest.raises(ConfigError):
        Config.from_dict({"audit": {"enabled": True, "workspace": ["/x"]}})


def test_network_and_database_config():
    cfg = Config.from_dict(
        {
            "network": {
                "enabled": True,
                "include_unix": False,
                "db_ports": {"5432": "postgresql"},
                "ignore_ports": [443],
            },
            "database": {"enabled": True, "sqlite_suffixes": [".sqlite"]},
        }
    )
    assert cfg.network.enabled is True
    assert cfg.network.db_ports[5432] == "postgresql"
    assert cfg.network.include_unix is False
    assert cfg.database.enabled is True


def test_db_audit_config():
    cfg = Config.from_dict(
        {
            "db_audit": {
                "enabled": True,
                "sources": [{"system": "postgres", "path": "/tmp/pg.log"}],
                "sensitive_tables": ["Accounts"],
            }
        }
    )
    assert cfg.db_audit.enabled is True
    assert cfg.db_audit.sources[0].system == "postgresql"
    assert cfg.db_audit.sensitive_tables == ["accounts"]
