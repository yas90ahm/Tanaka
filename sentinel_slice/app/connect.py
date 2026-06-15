# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Connect Sentinel to an AI — MCP host configuration, done for the user.

"Connect it to your AI" means one concrete thing: write a Sentinel entry into
the host app's MCP config so the host launches `sentinel-mcp` and routes its
tool calls through the governance gateway. Dad will never open
`claude_desktop_config.json`; this module is what edits it for him — safely,
idempotently, and reversibly, without clobbering any other MCP servers he has.

Hosts share one shape: a JSON file with a top-level `mcpServers` object keyed
by a server name. We add/remove exactly our key and touch nothing else.

Pure and side-effect-narrow (it only reads/writes the one config file): no
GUI, no network. The shell calls these; tests drive them against temp files.

HONEST SCOPE: "connect to any AI" = any host that speaks MCP over a local
process and reads one of these config files. A website-only assistant has no
local process to govern, so there is nothing to connect. Host config formats
evolve; the three below are the stable, documented ones.
"""

import json
import os
import sys
from dataclasses import dataclass

# Our entry in every host's mcpServers map.
SERVER_KEY = "sentinel"


@dataclass(frozen=True)
class McpHost:
    """One MCP host app and where its config lives on this machine."""
    key: str
    display_name: str
    config_path: str
    note: str = ""


def _home() -> str:
    return os.path.expanduser("~")


def known_hosts(environ=None, platform=None) -> list[McpHost]:
    """The MCP hosts we know how to configure, with config paths resolved for
    this platform. Listed whether or not the host is installed (see
    `is_installed`)."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    home = _home()

    if plat == "win32":
        appdata = env.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        claude_desktop = os.path.join(appdata, "Claude", "claude_desktop_config.json")
    elif plat == "darwin":
        claude_desktop = os.path.join(
            home, "Library", "Application Support", "Claude",
            "claude_desktop_config.json")
    else:
        config_home = env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        claude_desktop = os.path.join(
            config_home, "Claude", "claude_desktop_config.json")

    return [
        McpHost("claude_desktop", "Claude Desktop", claude_desktop),
        McpHost("claude_code", "Claude Code",
                os.path.join(home, ".claude.json"),
                note="global MCP servers"),
        McpHost("cursor", "Cursor",
                os.path.join(home, ".cursor", "mcp.json")),
    ]


def get_host(key: str, environ=None, platform=None) -> McpHost | None:
    for host in known_hosts(environ, platform):
        if host.key == key:
            return host
    return None


def gateway_command(python_exe=None, extra_args=None) -> dict:
    """The server spec to register: launch the gateway via `python -m` against
    THIS interpreter (robust regardless of PATH or how the host spawns it).
    Defaults add `--sandbox auto` so an enabled AppContainer is used
    automatically."""
    args = ["-m", "sentinel_slice.mcp_gateway"]
    args += list(extra_args) if extra_args is not None else ["--sandbox", "auto"]
    return {"command": python_exe or sys.executable, "args": args}


def is_installed(host: McpHost) -> bool:
    """True if the host appears installed: its config directory exists (the
    app created it), even if the config file itself doesn't yet."""
    return os.path.isdir(os.path.dirname(host.config_path))


def read_config(host: McpHost) -> dict:
    """The host's current config as a dict. A missing or unparseable file
    reads as an empty config (we never crash on the user's own file; a BOM
    from a Windows editor is tolerated)."""
    try:
        with open(host.config_path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def is_connected(host: McpHost) -> bool:
    servers = read_config(host).get("mcpServers")
    return isinstance(servers, dict) and SERVER_KEY in servers


def _write_config(host: McpHost, config: dict) -> None:
    os.makedirs(os.path.dirname(host.config_path), exist_ok=True)
    with open(host.config_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, sort_keys=True)
        fh.write("\n")


def connect(host: McpHost, server_spec: dict | None = None) -> str:
    """Register Sentinel in the host's config. Preserves every other
    mcpServers entry and every other top-level key. Returns "added" (new) or
    "updated" (our entry already existed and changed/stayed). Idempotent."""
    spec = server_spec if server_spec is not None else gateway_command()
    config = read_config(host)
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    existed = SERVER_KEY in servers
    servers[SERVER_KEY] = spec
    config["mcpServers"] = servers
    _write_config(host, config)
    return "updated" if existed else "added"


def disconnect(host: McpHost) -> str:
    """Remove Sentinel from the host's config, leaving everything else
    untouched. Returns "removed" or "absent" (nothing to do)."""
    config = read_config(host)
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or SERVER_KEY not in servers:
        return "absent"
    del servers[SERVER_KEY]
    config["mcpServers"] = servers
    _write_config(host, config)
    return "removed"


def status(environ=None, platform=None) -> list[dict]:
    """A row per known host: installed? connected? — the Connect screen's
    model."""
    out = []
    for host in known_hosts(environ, platform):
        out.append({
            "key": host.key,
            "display_name": host.display_name,
            "config_path": host.config_path,
            "installed": is_installed(host),
            "connected": is_connected(host),
            "note": host.note,
        })
    return out
