"""Structural blindness — the cashier/menu modules have NO import path to
kitchen/ and read no fixture mailbox.

Two independent, both-required assertions:

1. Fresh-subprocess sys.modules check: a child that imports all four
   cashier/menu modules must end with NO 'sentinel_slice.kitchen' (or
   submodule) present in sys.modules.
2. Source-grep check: in each module's source, no line that is an `import`
   or `from` statement may contain the substring "kitchen".
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PKG_DIR = Path(__file__).resolve().parents[1]

CASHIER_MENU_FILES = [
    PKG_DIR / "cashier" / "engine.py",
    PKG_DIR / "cashier" / "policy.py",
    PKG_DIR / "cashier" / "store.py",
    PKG_DIR / "menu" / "catalog.py",
]


def test_cashier_loads_no_kitchen_module_in_fresh_subprocess():
    child = (
        "import sys\n"
        "import sentinel_slice.cashier.engine\n"
        "import sentinel_slice.cashier.policy\n"
        "import sentinel_slice.cashier.store\n"
        "import sentinel_slice.menu.catalog\n"
        "bad = [m for m in sys.modules "
        "if m == 'sentinel_slice.kitchen' "
        "or m.startswith('sentinel_slice.kitchen.')]\n"
        "assert not bad, bad\n"
        "print('OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", child],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "OK"


def test_no_kitchen_substring_in_any_cashier_import_line():
    for path in CASHIER_MENU_FILES:
        assert path.exists(), path
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                assert "kitchen" not in line, (str(path), line)
