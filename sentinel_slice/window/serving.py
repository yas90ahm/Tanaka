"""The serving window — the PERSISTENT content path handed to the diner.

This is NOT the chef's ephemeral workspace. The runner gives the chef a fresh
tempdir as cwd (destroyed on exit); the chef writes its output into the window
dir resolved here, which survives. The artifact is ALWAYS a single file named
`output.txt` under `<root>/<order_id>/`, whatever the capability — a drafted
reply, a summary, a payment request. (Historically this was `draft.txt`, back
when the only capability was email; it is generic now.)

stdlib only (`os`). Tests pass a temp `root` so nothing pollutes the repo.
"""

import os

# The canonical per-order output artifact filename. One capability, one order,
# one output file — content varies by capability; the name does not.
OUTPUT_FILENAME = "output.txt"

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
    """Return <window_dir(order_id, root)>/output.txt (does NOT need to exist).
    Filename is FROZEN as OUTPUT_FILENAME to match chef_main. (Function name
    kept as draft_path for call-site stability; the file is the generic
    per-order output.)"""
    return os.path.join(window_dir(order_id, root), OUTPUT_FILENAME)


def read_draft(order_id: str, root: str | None = None) -> bytes:
    """Return the bytes of the order's output file (open 'rb'). Raises
    FileNotFoundError if absent."""
    with open(draft_path(order_id, root), "rb") as f:
        return f.read()
