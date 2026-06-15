# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Keygen — the one cashier/ledger Ed25519 keypair, PEM on disk.

The private key is the slice's single credential. It is gitignored and lives
only in `sentinel_slice/keys/`; the public key is committed so the standalone
verifier can validate the chain.

REGENERATION IS DESTRUCTIVE TO VERIFIABILITY: receipts already signed by the
old key will FAIL verification against a new public key. `main` therefore
refuses to overwrite an existing keypair unless invoked with --force, and a
forced regeneration means any previously signed ledger db must be retired.
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Module-relative (NOT cwd-relative) so keygen works from any directory and
# as an installed console script.
KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "cashier_ed25519_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "cashier_ed25519_public.pem")


def generate_keypair(keys_dir) -> tuple[str, str]:
    """Generate one Ed25519 keypair and write both PEMs into keys_dir.

    Returns the tuple (private_path, public_path) of the two files written.
    """
    os.makedirs(keys_dir, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path = os.path.join(keys_dir, "cashier_ed25519_private.pem")
    public_path = os.path.join(keys_dir, "cashier_ed25519_public.pem")

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)

    return (private_path, public_path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-keygen",
        description="Generate the cashier/ledger Ed25519 keypair (PEM on disk).",
    )
    parser.add_argument(
        "--keys",
        default=None,
        metavar="DIR",
        help="directory to write the keypair into (default: the package's "
        "committed sentinel_slice/keys). The existence/overwrite checks and "
        "the writes all target THIS directory.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="regenerate even if a private key already exists in the target "
        "dir (retires every ledger the old key signed).",
    )
    args = parser.parse_args(argv)

    # Resolve every path from the chosen directory — NOT the module constant —
    # so the checks and the writes can never disagree about which keypair this
    # invocation is touching.
    keys_dir = os.path.abspath(args.keys) if args.keys else KEYS_DIR
    private_path = os.path.join(keys_dir, "cashier_ed25519_private.pem")
    public_path = os.path.join(keys_dir, "cashier_ed25519_public.pem")

    private_exists = os.path.isfile(private_path)
    public_exists = os.path.isfile(public_path)

    # The PRIVATE key is the only irreplaceable artifact: regenerating it
    # retires every ledger it ever signed. That — and only that — requires
    # --force. (A committed PUBLIC key with no private key is the normal
    # fresh-clone/demo state; replacing it is safe and is exactly what a new
    # operator must do, so we don't make them fight the tool for it.)
    if private_exists and not args.force:
        print("refusing to overwrite existing keypair:")
        for p in (private_path, public_path):
            if os.path.isfile(p):
                print("  " + p)
        print(
            "Regenerating breaks verification of every ledger signed by the "
            "old key. Re-run with --force only if you intend to retire those "
            "ledgers."
        )
        return 1

    if private_exists and args.force:
        print(
            "WARNING: overwriting the cashier keypair at {}. Previously signed "
            "ledgers (including a committed ledger.db) will no longer verify "
            "against the new public key.".format(keys_dir)
        )
    elif public_exists:
        # Fresh clone: the repo shipped a demo public key but no private key.
        print(
            "Note: a demo public key shipped with the repo but this clone has "
            "no private key. Creating your own keypair now. The committed demo "
            "ledger.db was signed by the demo key (still verifiable via git "
            "history); start a fresh ledger for your own runs."
        )

    written_private, written_public = generate_keypair(keys_dir)
    print(written_private)
    print(written_public)
    return 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
