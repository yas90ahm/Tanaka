"""The serving window — the PERSISTENT content path handed to the diner.

This is NOT the chef's ephemeral workspace. The runner gives the chef a fresh
tempdir as cwd (destroyed on exit); the chef writes its draft into the window
dir resolved here, which survives. Filenames are FROZEN to match
`chef_main.py` §1e: the draft is always `draft.txt` under `<root>/<order_id>/`.

stdlib only (`os`). Tests pass a temp `root` so nothing pollutes the repo.
"""

import os

WINDOW_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "orders")
)  # sentinel_slice/window/orders  (gitignored; tests pass a temp root)


def window_dir(order_id: str, root: str | None = None) -> str:
    """Return abs path to <root>/<order_id>, creating it
    (makedirs exist_ok=True). Default root=WINDOW_ROOT."""
    base = WINDOW_ROOT if root is None else root
    path = os.path.abspath(os.path.join(base, order_id))
    os.makedirs(path, exist_ok=True)
    return path


def draft_path(order_id: str, root: str | None = None) -> str:
    """Return <window_dir(order_id, root)>/draft.txt (does NOT need to exist).
    Filename is FROZEN as 'draft.txt' to match chef_main §1e."""
    return os.path.join(window_dir(order_id, root), "draft.txt")


def read_draft(order_id: str, root: str | None = None) -> bytes:
    """Return the bytes of draft.txt for order_id (open 'rb'). Raises
    FileNotFoundError if absent."""
    with open(draft_path(order_id, root), "rb") as f:
        return f.read()
