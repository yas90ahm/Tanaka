"""App model — the data and actions behind the door's three screens.

A thin, GUI-free layer the tkinter shell renders. It composes pieces already
built and tested: `app.connect` (MCP hosts), `consumer.preferences` +
`menu.catalog` (permissions), and `inspector` (activity). File I/O only, no
tkinter — so every screen's data and every button's effect is testable
headless; the shell is then a dumb view.
"""

import os

from sentinel_slice import apphome
from sentinel_slice.app import connect
from sentinel_slice.consumer.preferences import ALLOW, ASK, BLOCK, Preferences
from sentinel_slice.menu.catalog import CUSTOM_CAPABILITIES_DIR, load_catalog

_STATE_LABEL = {ALLOW: "Allow", ASK: "Ask each time", BLOCK: "Block"}


class AppModel:
    def __init__(self, home: str, *, environ=None, platform=None) -> None:
        self._home = home
        self._environ = environ
        self._platform = platform
        self._prefs_path = apphome.preferences_path(home)
        self._prefs = Preferences.load(self._prefs_path)

    @property
    def home(self) -> str:
        return self._home

    # ---- Connect screen ----
    def connect_rows(self) -> list[dict]:
        return connect.status(self._environ, self._platform)

    def toggle_connection(self, host_key: str) -> str:
        """Connect if disconnected, disconnect if connected. Returns the
        action taken ("added"/"updated"/"removed"/"absent")."""
        host = connect.get_host(host_key, self._environ, self._platform)
        if host is None:
            raise ValueError("unknown host: {}".format(host_key))
        if connect.is_connected(host):
            return connect.disconnect(host)
        return connect.connect(host)

    # ---- Permissions screen ----
    def permission_rows(self) -> list[dict]:
        """Every menu capability with the state that currently applies and
        whether it's an explicit choice or the sensible default."""
        catalog = load_catalog(custom_dir=CUSTOM_CAPABILITIES_DIR)
        rows = []
        for cap in sorted(catalog.values(), key=lambda c: c.id):
            state = self._prefs.effective_state(cap)
            rows.append({
                "id": cap.id,
                "name": cap.name,
                "risk": cap.risk_class,
                "state": state,
                "state_label": _STATE_LABEL[state],
                "is_default": self._prefs.explicit(cap.id) is None,
            })
        return rows

    def set_permission(self, capability_id: str, state: str) -> str:
        """Set and PERSIST a permission. Returns the saved file path."""
        self._prefs.set(capability_id, state)
        return self._prefs.save(self._prefs_path)

    # ---- Activity screen ----
    def activity_report(self) -> dict:
        """The inspector's day-at-a-glance over the app-home ledger. A ledger
        that doesn't exist yet (no orders) reports empty, not an error."""
        from sentinel_slice import inspector

        ledger = apphome.ledger_path(self._home)
        if not os.path.exists(ledger):
            return {"empty": True, "fulfilled": 0, "rejected": 0,
                    "findings": [], "chain_valid": True}
        public_key = self._load_public_key()
        rows = inspector.read_rows(ledger)
        report = inspector.build_report(rows, public_key)
        report["empty"] = not rows
        return report

    def activity_text(self) -> str:
        from sentinel_slice import inspector

        report = self.activity_report()
        if report.get("empty") and report.get("fulfilled", 0) == 0 \
                and report.get("rejected", 0) == 0 and not report.get("findings"):
            return ("No activity yet. When your AI uses a tool, every action — "
                    "allowed or refused — will show up here with a verifiable "
                    "receipt.")
        return inspector.render_text(report)

    def _load_public_key(self):
        from cryptography.hazmat.primitives import serialization

        pub_path = apphome.public_key_path(self._home)
        try:
            with open(pub_path, "rb") as fh:
                return serialization.load_pem_public_key(fh.read())
        except (OSError, ValueError):
            return None
