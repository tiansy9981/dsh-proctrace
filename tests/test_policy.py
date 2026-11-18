import pytest

from proctrace.model import ProcessInfo
from proctrace.policy import ConfigError, Policy, Rule


def proc(**kwargs):
    defaults = dict(pid=100, ppid=1, name="python", exe="/usr/bin/python3",
                    cmdline=["python3", "app.py"], uid=501, create_time=1000.0)
    defaults.update(kwargs)
    return ProcessInfo(**defaults)


def test_rule_and_semantics():
    rule = Rule(name="py*", uid=501)
    assert rule.matches(proc())
    assert not rule.matches(proc(name="node"))
    assert not rule.matches(proc(uid=502))


def test_rule_glob_and_regex():
    assert Rule(name="py?hon").matches(proc())
    assert Rule(exe="/usr/bin/*").matches(proc())
    assert Rule(cmdline=r"app\.py$").matches(proc())
    assert not Rule(cmdline=r"^node").matches(proc())


def test_rule_create_time_pid_reuse():
    rule = Rule(pid=100, create_time=1000.0)
    assert rule.matches(proc(create_time=1000.5))
    assert not rule.matches(proc(create_time=1200.0))
    assert not rule.matches(proc(pid=101, create_time=1000.0))


def test_rule_requires_pid_for_create_time():
    with pytest.raises(ConfigError):
        Rule(create_time=1.0)


def test_rule_rejects_unknown_field():
    with pytest.raises(ConfigError):
        Rule.from_dict({"nam": "python"})


def test_rule_rejects_bad_regex():
    with pytest.raises(ConfigError):
        Rule.from_dict({"cmdline": "["})


def test_policy_resolves_all_and_direct_pid():
    procs = [proc(pid=10, name="secret"), proc(pid=11, name="other")]
    policy = Policy([Rule(name="sec*")], [Rule(name="oth*")])
    match = policy.resolve(procs)
    assert set(match.protected) == {10}
    assert match.excluded == {11}
    assert policy.is_protected_pid(10)
    assert policy.is_excluded_pid(11)

    direct = Policy([Rule(pid=42)], [])
    match = direct.resolve(None)
    assert set(match.protected) == {42}
    assert direct.needs_full_scan is False


def test_policy_needs_full_scan():
    assert Policy([Rule(pid=1)], []).needs_full_scan is False
    assert Policy([Rule(name="x")], []).needs_full_scan is True
    assert Policy([], [Rule(pid=1)]).needs_full_scan is False
    assert Policy([Rule(pid=1, create_time=1000.0)], []).needs_full_scan is True


def test_policy_local_match_helpers():
    policy = Policy([Rule(name="sec*")], [Rule(uid=502)])
    assert policy.match_protected(proc(name="secret")) is not None
    assert policy.match_protected(proc(name="other")) is None
    assert policy.match_excluded(proc(uid=502)) is not None
    assert policy.match_excluded(proc(uid=501)) is None
