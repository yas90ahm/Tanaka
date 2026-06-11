"""The door — a tkinter shell over the app model.

Three screens a non-technical person can use without a terminal:
  Connect      — turn Sentinel on for your AI (Claude Desktop, etc.)
  Permissions  — Allow / Ask / Block, per capability
  Activity     — what your AI did, in plain words, with verifiable receipts

Deliberately THIN: all data and every button effect come from `app.model`
(headless, tested). This file only lays out widgets and wires clicks to model
methods, then refreshes. tkinter is stdlib (the deps non-negotiable holds);
the real window is exercised by an env-gated GUI test, like the on-device
approval dialog.

HONEST SCOPE: this is the app's WINDOW, not a signed platform installer
(MSI/DMG), not auto-update, not a background service. It is the operator's
Settings surface; the governance it configures is the real product.
"""

import sys

from sentinel_slice.app.model import AppModel


def build_app(root, model: AppModel) -> dict:
    """Populate `root` (a Tk/Toplevel) with the three screens. Returns a dict
    of the refreshable screen-builders (so tests can invoke a refresh without
    a mainloop)."""
    import tkinter as tk
    from tkinter import ttk

    root.title("Sentinel Loop")
    root.geometry("640x520")
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    connect_tab = ttk.Frame(notebook, padding=12)
    perms_tab = ttk.Frame(notebook, padding=12)
    activity_tab = ttk.Frame(notebook, padding=12)
    notebook.add(connect_tab, text="Connect")
    notebook.add(perms_tab, text="Permissions")
    notebook.add(activity_tab, text="Activity")

    refreshers = {}

    # ---- Connect ----
    def render_connect():
        for w in connect_tab.winfo_children():
            w.destroy()
        ttk.Label(connect_tab, text="Turn Sentinel on for your AI",
                  font=("", 12, "bold")).pack(anchor="w", pady=(0, 8))
        for row in model.connect_rows():
            line = ttk.Frame(connect_tab)
            line.pack(fill="x", pady=4)
            state = ("connected" if row["connected"]
                     else "installed" if row["installed"]
                     else "not installed")
            ttk.Label(line, text="{}  ·  {}".format(row["display_name"], state),
                      width=40).pack(side="left")
            btn_text = "Disconnect" if row["connected"] else "Connect"

            def _toggle(key=row["key"]):
                model.toggle_connection(key)
                render_connect()
            ttk.Button(line, text=btn_text, command=_toggle).pack(side="right")
    refreshers["connect"] = render_connect

    # ---- Permissions ----
    def render_perms():
        for w in perms_tab.winfo_children():
            w.destroy()
        ttk.Label(perms_tab, text="What may your AI do?",
                  font=("", 12, "bold")).pack(anchor="w", pady=(0, 8))
        for row in model.permission_rows():
            line = ttk.Frame(perms_tab)
            line.pack(fill="x", pady=3)
            ttk.Label(line, text="{} ({})".format(row["name"], row["risk"]),
                      width=38).pack(side="left")
            choice = tk.StringVar(value=row["state"])

            def _set(cap_id=row["id"], var=choice):
                model.set_permission(cap_id, var.get())
                render_perms()
            box = ttk.Combobox(line, textvariable=choice, width=14,
                               state="readonly",
                               values=["allow", "ask", "block"])
            box.pack(side="right")
            box.bind("<<ComboboxSelected>>", lambda _e, f=_set: f())
    refreshers["perms"] = render_perms

    # ---- Activity ----
    def render_activity():
        for w in activity_tab.winfo_children():
            w.destroy()
        header = ttk.Frame(activity_tab)
        header.pack(fill="x")
        ttk.Label(header, text="What your AI did",
                  font=("", 12, "bold")).pack(side="left")
        ttk.Button(header, text="Refresh", command=render_activity).pack(side="right")
        text = tk.Text(activity_tab, wrap="word", height=24)
        text.pack(fill="both", expand=True, pady=(8, 0))
        text.insert("1.0", model.activity_text())
        text.configure(state="disabled")
    refreshers["activity"] = render_activity

    render_connect()
    render_perms()
    render_activity()
    return refreshers


def run(home=None, *, _test_autoclose_ms=None) -> int:
    """First-run readiness, then open the window. `_test_autoclose_ms` (test
    only) schedules the window to close itself so the GUI path runs headless
    under SENTINEL_TEST_GUI=1."""
    import tkinter as tk

    from sentinel_slice import apphome
    from sentinel_slice.app.firstrun import ensure_ready

    if home is None:
        home = apphome.default_app_home()
    ensure_ready(home)

    root = tk.Tk()
    model = AppModel(home)
    build_app(root, model)
    if _test_autoclose_ms is not None:
        root.after(_test_autoclose_ms, root.destroy)
    root.mainloop()
    return 0


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel-app",
        description="Sentinel Loop — the desktop app: connect your AI, set "
        "permissions, see what it did.")
    parser.add_argument("--home", default=None,
                        help="app home (default: platform per-user dir)")
    args = parser.parse_args(argv)
    return run(home=args.home)


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
