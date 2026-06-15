# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""SPEC acceptance #7 — the chef has no network reach.

Two distinct, complementary bars:

1. **Our own source** — grep `chef_main.py` and assert it imports NONE of
   socket/http/urllib/requests. The chef we write never even references a
   network module. Strict, by name (`NET_MODULES`).

2. **The runtime closure** — load `chef_main.py` BY FILE PATH in a fresh
   subprocess and assert no network-EGRESS-capable module is present in
   `sys.modules` (`NET_EGRESS`). We anchor on `socket` — the linchpin every
   Python egress path (`urllib.request`, `http.client`, `requests`, `ssl`,
   `ftplib`, `smtplib`) is built on — so its absence means the chef cannot open
   a connection at all.

   We deliberately do NOT flag the bare `urllib`/`http` namespaces: `urllib.parse`
   is pure URL-string parsing with zero egress, and a TRUSTED dependency
   (`cryptography`, needed for Ed25519) pulls `urllib.parse` in transitively on
   some Python versions (3.11/3.12) but not others (3.13+). Flagging the bare
   namespace made this acceptance test a version-dependent false positive while
   proving nothing about network reach. The egress-capable check is both
   stricter (it would catch `urllib.request`, which the bare-name check on the
   already-present `urllib` could not distinguish) and version-robust.
"""

import subprocess
import sys
from pathlib import Path

CHEF_MAIN = Path(__file__).resolve().parents[1] / "chef" / "chef_main.py"

# Bar 1 (our source): the chef must not even import these, by name.
NET_MODULES = ("socket", "http", "urllib", "requests")

# Bar 2 (runtime closure): network-EGRESS-capable modules only. Bare namespace
# packages whose only loaded submodule is harmless (urllib -> urllib.parse) are
# excluded; only urllib.request / http.client carry egress, and — like every
# entry here — they cannot function without `socket`, the linchpin.
NET_EGRESS = (
    "socket", "ssl", "http.client", "http.server",
    "urllib.request", "ftplib", "smtplib", "requests",
)


def test_at07_chef_import_closure_has_no_network():
    egress_literal = "(" + ",".join(repr(m) for m in NET_EGRESS) + ")"
    prog = (
        "import importlib.util, sys;"
        f"spec=importlib.util.spec_from_file_location('chef_main', r'{CHEF_MAIN}');"
        "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
        f"bad=[x for x in {egress_literal} if x in sys.modules];"
        "print('BAD='+','.join(bad)); sys.exit(1 if bad else 0)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", prog],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == "BAD="


def test_at07_chef_source_imports_no_network():
    src = CHEF_MAIN.read_text(encoding="utf-8")
    for mod in NET_MODULES:
        assert f"import {mod}" not in src, mod
        assert f"from {mod}" not in src, mod
