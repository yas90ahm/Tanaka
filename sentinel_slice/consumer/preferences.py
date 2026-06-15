# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Personal permissions — the non-technical "what may my agent do?" settings.

No JSON, no roles, no policy authoring. Three states per capability, like a
phone's app permissions:

    ALLOW  — let the agent do it without asking.
    ASK    — prompt me each time (allow once / deny).
    BLOCK  — never; auto-deny and record it, don't even ask.

If you never set a capability, its default is sensible: ASK for high-stakes
actions (those flagged requires_user_confirmation), ALLOW for low-stakes ones —
so routine things just work and risky things check with you. You can override
any capability to any state, including BLOCK on something low-stakes you simply
don't want your agent touching.

These preferences sit ON TOP of policy: the cashier still decides what's even
possible; this decides what YOU additionally permit. Persisted as a small JSON
file so the choices stick between runs.
"""

import json

ALLOW = "allow"
ASK = "ask"
BLOCK = "block"
STATES = (ALLOW, ASK, BLOCK)


class Preferences:
    def __init__(self, settings: dict | None = None, *, path: str | None = None) -> None:
        self._settings: dict[str, str] = {}
        for cap_id, state in (settings or {}).items():
            self.set(cap_id, state)
        self._path = path

    def effective_state(self, capability) -> str:
        """The state that applies to `capability`: the user's explicit choice
        if any, else the sensible default (ASK for confirmation-required
        capabilities, ALLOW otherwise)."""
        explicit = self._settings.get(capability.id)
        if explicit is not None:
            return explicit
        return ASK if capability.requires_user_confirmation else ALLOW

    def explicit(self, capability_id: str) -> str | None:
        """The user's explicit setting for a capability, or None if unset
        (defaulted)."""
        return self._settings.get(capability_id)

    def set(self, capability_id: str, state: str) -> None:
        if state not in STATES:
            raise ValueError("state must be one of {}".format(STATES))
        self._settings[capability_id] = state

    def clear(self, capability_id: str) -> None:
        """Forget an explicit setting (revert to the default)."""
        self._settings.pop(capability_id, None)

    def as_dict(self) -> dict[str, str]:
        return dict(self._settings)

    # ---- persistence ----
    @classmethod
    def load(cls, path: str) -> "Preferences":
        """Load from a JSON file. A missing file yields empty preferences
        (everything defaulted) — so a first run just works."""
        try:
            # utf-8-sig tolerates a BOM, which Windows editors (Notepad,
            # PowerShell Out-File) often prepend — a non-technical user must
            # not get a crash for editing their own settings file.
            with open(path, "r", encoding="utf-8-sig") as fh:
                settings = json.load(fh)
        except FileNotFoundError:
            settings = {}
        return cls(settings, path=path)

    def save(self, path: str | None = None) -> str:
        """Write preferences as JSON (sorted, stable). Returns the path."""
        target = path or self._path
        if target is None:
            raise ValueError("no path to save preferences to")
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(self._settings, fh, indent=2, sort_keys=True)
            fh.write("\n")
        return target

    def save_if_persistent(self) -> str | None:
        """Save when these preferences came from a file ("Always allow" must
        outlive the session); a no-op for in-memory preferences (tests,
        ephemeral demos). Returns the path written, or None."""
        if self._path is None:
            return None
        return self.save()
