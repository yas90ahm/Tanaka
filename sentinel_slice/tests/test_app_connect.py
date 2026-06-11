"""Connect logic (v0.13) — wiring Sentinel into an MCP host's config.

The safety-critical promises, pinned exactly: connect adds our entry under
mcpServers WITHOUT touching the user's other servers or other top-level keys;
it is idempotent; disconnect removes ONLY our entry; a missing/garbage config
is tolerated; the gateway command is the robust `python -m` form; per-platform
Claude Desktop paths resolve correctly; and status reports installed/connected.
"""

import json
import os
import sys

from sentinel_slice.app import connect
from sentinel_slice.app.connect import (
    McpHost,
    SERVER_KEY,
    connect as do_connect,
    disconnect,
    gateway_command,
    is_connected,
    is_installed,
    known_hosts,
    read_config,
    status,
)


def _host(tmp_path, name="claude_desktop_config.json"):
    return McpHost("test_host", "Test Host", str(tmp_path / "cfg" / name))


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def test_gateway_command_is_python_dash_m_form():
    spec = gateway_command(python_exe="PY")
    assert spec == {
        "command": "PY",
        "args": ["-m", "sentinel_slice.mcp_gateway", "--sandbox", "auto"],
    }
    # Defaults to the running interpreter.
    assert gateway_command()["command"] == sys.executable


def test_connect_creates_config_with_our_entry(tmp_path):
    host = _host(tmp_path)
    action = do_connect(host, {"command": "x", "args": ["-m", "g"]})
    assert action == "added"
    cfg = _read(host.config_path)
    assert cfg == {"mcpServers": {SERVER_KEY: {"command": "x", "args": ["-m", "g"]}}}
    assert is_connected(host) is True


def test_connect_preserves_other_servers_and_keys(tmp_path):
    host = _host(tmp_path)
    os.makedirs(os.path.dirname(host.config_path), exist_ok=True)
    with open(host.config_path, "w", encoding="utf-8") as fh:
        json.dump({
            "mcpServers": {"someoneElse": {"command": "other"}},
            "theme": "dark",
        }, fh)

    do_connect(host, {"command": "x", "args": []})

    cfg = _read(host.config_path)
    # Our entry was added...
    assert cfg["mcpServers"][SERVER_KEY] == {"command": "x", "args": []}
    # ...the other server is UNTOUCHED...
    assert cfg["mcpServers"]["someoneElse"] == {"command": "other"}
    # ...and unrelated top-level keys survive.
    assert cfg["theme"] == "dark"


def test_connect_is_idempotent_and_reports_updated(tmp_path):
    host = _host(tmp_path)
    assert do_connect(host, {"command": "x", "args": []}) == "added"
    assert do_connect(host, {"command": "x", "args": []}) == "updated"
    cfg = _read(host.config_path)
    # Exactly one entry; not duplicated.
    assert list(cfg["mcpServers"].keys()) == [SERVER_KEY]


def test_disconnect_removes_only_our_entry(tmp_path):
    host = _host(tmp_path)
    os.makedirs(os.path.dirname(host.config_path), exist_ok=True)
    with open(host.config_path, "w", encoding="utf-8") as fh:
        json.dump({"mcpServers": {
            SERVER_KEY: {"command": "x"},
            "someoneElse": {"command": "other"},
        }}, fh)

    assert disconnect(host) == "removed"

    cfg = _read(host.config_path)
    assert SERVER_KEY not in cfg["mcpServers"]
    assert cfg["mcpServers"]["someoneElse"] == {"command": "other"}
    assert is_connected(host) is False


def test_disconnect_absent_is_a_noop(tmp_path):
    host = _host(tmp_path)
    os.makedirs(os.path.dirname(host.config_path), exist_ok=True)
    with open(host.config_path, "w", encoding="utf-8") as fh:
        json.dump({"mcpServers": {"someoneElse": {"command": "other"}}}, fh)
    assert disconnect(host) == "absent"
    assert _read(host.config_path)["mcpServers"] == {"someoneElse": {"command": "other"}}


def test_missing_and_garbage_config_tolerated(tmp_path):
    host = _host(tmp_path)
    assert read_config(host) == {}          # missing file
    assert is_connected(host) is False
    os.makedirs(os.path.dirname(host.config_path), exist_ok=True)
    with open(host.config_path, "w", encoding="utf-8") as fh:
        fh.write("not json {{{")
    assert read_config(host) == {}          # garbage
    # connect still works (overwrites the garbage with valid config).
    do_connect(host, {"command": "x", "args": []})
    assert is_connected(host) is True


def test_config_with_utf8_bom_tolerated(tmp_path):
    host = _host(tmp_path)
    os.makedirs(os.path.dirname(host.config_path), exist_ok=True)
    with open(host.config_path, "w", encoding="utf-8-sig") as fh:
        json.dump({"mcpServers": {SERVER_KEY: {"command": "x"}}}, fh)
    assert is_connected(host) is True       # BOM did not break parsing


def test_is_installed_checks_config_dir(tmp_path):
    host = _host(tmp_path)
    assert is_installed(host) is False
    os.makedirs(os.path.dirname(host.config_path))
    assert is_installed(host) is True


def test_claude_desktop_path_per_platform():
    win = {h.key: h for h in known_hosts(
        environ={"APPDATA": r"C:\Users\u\AppData\Roaming"}, platform="win32")}
    assert win["claude_desktop"].config_path == os.path.join(
        r"C:\Users\u\AppData\Roaming", "Claude", "claude_desktop_config.json")

    mac = {h.key: h for h in known_hosts(environ={}, platform="darwin")}
    assert mac["claude_desktop"].config_path == os.path.join(
        os.path.expanduser("~"), "Library", "Application Support", "Claude",
        "claude_desktop_config.json")

    lin = {h.key: h for h in known_hosts(
        environ={"XDG_CONFIG_HOME": "/x/cfg"}, platform="linux")}
    assert lin["claude_desktop"].config_path == os.path.join(
        "/x/cfg", "Claude", "claude_desktop_config.json")


def test_status_reports_installed_and_connected(tmp_path, monkeypatch):
    host = _host(tmp_path)
    monkeypatch.setattr(connect, "known_hosts",
                        lambda environ=None, platform=None: [host])
    rows = status()
    assert len(rows) == 1
    assert rows[0]["installed"] is False and rows[0]["connected"] is False
    do_connect(host, {"command": "x", "args": []})
    rows = status()
    assert rows[0]["installed"] is True and rows[0]["connected"] is True
