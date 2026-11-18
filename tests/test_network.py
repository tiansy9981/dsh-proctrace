from proctrace.config import NetworkConfig
from proctrace.network import Connection, NetworkMonitor


def conn(pid=10, fd=3, proto="tcp", local="127.0.0.1:50000", remote="127.0.0.1:5432",
         status="ESTABLISHED", service="postgresql"):
    return Connection(pid, fd, "inet", proto, local, remote, status, service)


def test_network_open_change_close_and_db():
    state = {10: [conn()]}
    monitor = NetworkMonitor(
        NetworkConfig(enabled=True), provider=lambda pid: state.get(pid, [])
    )
    events, errors = monitor.poll([10], show_initial=True)
    assert not errors
    assert [e.kind for e in events] == ["db_connect"]
    assert events[0].conn.service == "postgresql"
    assert monitor.connections_for(10)

    state[10] = [conn(status="CLOSE_WAIT")]
    events, _ = monitor.poll([10])
    assert [e.kind for e in events] == ["db_change"]
    assert events[0].old_status == "ESTABLISHED"

    state[10] = []
    events, _ = monitor.poll([10])
    assert [e.kind for e in events] == ["db_close"]


def test_network_non_db_and_unix():
    state = {
        10: [
            Connection(10, 4, "inet", "tcp", "127.0.0.1:50001", "1.2.3.4:443", "ESTABLISHED"),
            Connection(10, 5, "unix", "unix", "/tmp/.s.PGSQL.5432", "", "NONE", "postgresql"),
        ]
    }
    monitor = NetworkMonitor(NetworkConfig(enabled=True), provider=lambda pid: state.get(pid, []))
    events, _ = monitor.poll([10], show_initial=True)
    kinds = sorted(e.kind for e in events)
    assert kinds == ["db_connect", "net_open"]
    assert len(monitor.connections_for(10)) == 2


def test_network_ignore_ports():
    state = {10: [conn(remote="127.0.0.1:5432")]}
    monitor = NetworkMonitor(
        NetworkConfig(enabled=True, ignore_ports=[5432]),
        provider=lambda pid: state.get(pid, []),
    )
    events, _ = monitor.poll([10], show_initial=True)
    assert not events
    assert not monitor.all_connections()


def test_network_disabled():
    monitor = NetworkMonitor(NetworkConfig(enabled=False), provider=lambda pid: [conn()])
    events, _ = monitor.poll([10], show_initial=True)
    assert not events


def test_find_client_pid_by_client_endpoint():
    state = {10: [conn(local="127.0.0.1:55000", remote="10.0.0.9:5432")]}
    monitor = NetworkMonitor(NetworkConfig(enabled=True), provider=lambda pid: state.get(pid, []))
    monitor.poll([10])
    assert monitor.find_client_pid("127.0.0.1", 55000) == 10
    # Host-only logs are ambiguous only when multiple connections exist.
    assert monitor.find_client_pid("127.0.0.1") == 10
    state[10] = []
    monitor.poll([10])
    # Recent-connection cache keeps attribution shortly after close.
    assert monitor.find_client_pid("127.0.0.1", 55000) == 10
