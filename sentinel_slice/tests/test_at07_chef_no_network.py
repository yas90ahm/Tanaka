"""SPEC acceptance #7 — the chef has no network reach.

Two concrete proofs: (1) load chef_main.py BY FILE PATH in a fresh
subprocess and assert its resulting sys.modules contains NONE of
socket/http/urllib/requests; (2) grep the source text and assert neither
the `import X` nor the `from X` form of any of the four appears.
"""

import subprocess
import sys
from pathlib import Path

CHEF_MAIN = Path(__file__).resolve().parents[1] / "chef" / "chef_main.py"

NET_MODULES = ("socket", "http", "urllib", "requests")


def test_at07_chef_import_closure_has_no_network():
    prog = (
        "import importlib.util, sys;"
        f"spec=importlib.util.spec_from_file_location('chef_main', r'{CHEF_MAIN}');"
        "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
        "bad=[x for x in ('socket','http','urllib','requests') if x in sys.modules];"
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
