"""sentinel-init — first run of an installed Sentinel.

Creates the per-user app home (see `apphome.py`), generates the one cashier
Ed25519 keypair into it, and tells the user where everything lives and what
to do next. After this, every entry point (`sentinel-mcp`, the consumer demo,
the permissions editor) finds its state in the app home automatically — no
flags, no cwd dependence, nothing written into site-packages.

Same destructive-regeneration guard as `keygen.py`: an existing private key
is never overwritten without --force, because receipts signed by the old key
stop verifying under a new one.
"""

import argparse
import sys

from sentinel_slice import apphome
from sentinel_slice.keygen import generate_keypair

_NEXT_STEPS = """\
next steps:
  permissions   python -m sentinel_slice.consumer.permissions
  agent gateway sentinel-mcp   (every tool call governed + receipted)
  verify ledger sentinel-verify "{ledger}" "{pubkey}"

to connect an MCP host (e.g. Claude Desktop), add to its config:
  {{"mcpServers": {{"sentinel": {{"command": "sentinel-mcp"}}}}}}
"""


def main(argv=None, *, print_fn=print, environ=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-init",
        description="Set up the per-user Sentinel home: directories + the "
        "cashier keypair. Run once after install.")
    parser.add_argument(
        "--home", default=None,
        help="app home directory (default: the platform per-user location, "
        "or $SENTINEL_HOME)")
    parser.add_argument(
        "--force", action="store_true",
        help="overwrite an existing keypair (retires every ledger it signed)")
    parser.add_argument(
        "--sandbox", action="store_true",
        help="set up OS-level chef containment (Windows AppContainer): grants "
        "+ a marker so sentinel-mcp uses it automatically")
    args = parser.parse_args(argv)

    home = args.home if args.home is not None else apphome.default_app_home(
        environ=environ)
    apphome.ensure_app_home(home)

    if apphome.is_initialized(home) and not args.force:
        print_fn("already initialized: " + home)
        print_fn("  private key: " + apphome.private_key_path(home))
        print_fn(
            "Regenerating breaks verification of every ledger signed by the "
            "existing key. Re-run with --force only if you intend to retire "
            "those ledgers.")
        return 1

    if apphome.is_initialized(home) and args.force:
        print_fn(
            "WARNING: overwriting the cashier keypair. Previously signed "
            "ledgers in this home will no longer verify against the new "
            "public key.")

    private_path, public_path = generate_keypair(apphome.keys_dir(home))

    print_fn("initialized " + home)
    print_fn("  private key:  " + private_path + "  (never leaves this machine)")
    print_fn("  public key:   " + public_path)
    print_fn("  ledger:       " + apphome.ledger_path(home)
             + "  (created on first order)")
    print_fn("  permissions:  " + apphome.preferences_path(home))

    # OS-level chef containment (Windows AppContainer). Opt-in (--sandbox)
    # because it modifies ACLs on the Python runtime; an installer passes it,
    # a hand-run init gets a hint instead.
    _setup_sandbox(home, args.sandbox, print_fn)
    print_fn("")
    print_fn(_NEXT_STEPS.format(
        ledger=apphome.ledger_path(home), pubkey=public_path))
    return 0


def _setup_sandbox(home, requested, print_fn) -> None:
    """Set up the OS containment backend when asked and available; otherwise
    leave a hint. Records the chosen backend in the app-home marker so
    sentinel-mcp picks it up with no further flags."""
    from sentinel_slice.chef import appcontainer

    if not requested:
        if appcontainer.is_available():
            print_fn("  containment:  available — re-run with --sandbox to "
                     "enable the Windows AppContainer (OS-enforced)")
        return
    if not appcontainer.is_available():
        print_fn("  containment:  --sandbox requested but AppContainer is "
                 "unavailable here; the chef runs as a subprocess (contract).")
        return
    appcontainer.AppContainerSandbox.setup()
    marker = apphome.write_sandbox_backend(home, "appcontainer")
    print_fn("  containment:  Windows AppContainer ENABLED (no network, "
             "ACL-confined). marker: " + marker)


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
