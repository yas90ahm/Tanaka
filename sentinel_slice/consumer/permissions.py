# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Personal permissions editor — `python -m sentinel_slice.consumer.permissions`.

A plain, non-technical screen: list the things an agent could try, and set each
to Allow / Ask / Block. No JSON, no policy language. Choices are saved to a
small file the consumer loop reads.

    Allow  — let the agent do it without asking.
    Ask    — check with me each time.
    Block  — never let the agent do it.

The display/edit logic is pure functions so it's testable; `main()` is the thin
interactive loop (input/print injectable).
"""

import os
import sys

from sentinel_slice.apphome import resolve_runtime_paths
from sentinel_slice.consumer.preferences import ALLOW, ASK, BLOCK, Preferences
from sentinel_slice.menu.catalog import load_catalog

DEFAULT_PREFS_PATH = os.path.abspath("sentinel_permissions.json")


def default_prefs_path() -> str:
    """Where preferences live by default: the app home's permissions.json
    when sentinel-init has run, else the historical cwd file (dev checkout)."""
    return resolve_runtime_paths().preferences_path or DEFAULT_PREFS_PATH

_LABEL = {ALLOW: "Allow", ASK: "Ask each time", BLOCK: "Block"}
_CHOICE = {"a": ALLOW, "s": ASK, "b": BLOCK}


def render(catalog, prefs: Preferences) -> str:
    """The permissions screen as text: every capability, its risk, and the
    state that currently applies (with '(default)' when not explicitly set)."""
    lines = ["Your agent's permissions", ""]
    for i, cap in enumerate(sorted(catalog.values(), key=lambda c: c.id), start=1):
        state = prefs.effective_state(cap)
        tag = "" if prefs.explicit(cap.id) else "  (default)"
        lines.append("  {}. {:<28} risk:{:<5} -> {}{}".format(
            i, cap.id, cap.risk_class, _LABEL[state], tag))
        lines.append("       {}".format(cap.name))
    return "\n".join(lines)


def ordered_caps(catalog):
    return sorted(catalog.values(), key=lambda c: c.id)


def main(argv=None, *, input_fn=input, print_fn=print) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else default_prefs_path()

    catalog = load_catalog()
    prefs = Preferences.load(path)
    caps = ordered_caps(catalog)

    while True:
        print_fn(render(catalog, prefs))
        print_fn("")
        raw = input_fn(
            "Number to change (blank = save & quit): ").strip()
        if not raw:
            break
        if not raw.isdigit() or not (1 <= int(raw) <= len(caps)):
            print_fn("  (not a listed number)")
            continue
        cap = caps[int(raw) - 1]
        choice = input_fn(
            "  [a]llow / a[s]k / [b]lock for {}? ".format(cap.id)
        ).strip().lower()
        if choice in _CHOICE:
            prefs.set(cap.id, _CHOICE[choice])
        else:
            print_fn("  (unchanged)")

    saved = prefs.save(path)
    print_fn("saved {}".format(saved))
    return 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
