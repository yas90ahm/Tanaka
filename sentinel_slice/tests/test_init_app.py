# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""sentinel-init (v0.10) — first run of an installed Sentinel.

Pins: a fresh init exits 0, creates exactly the app-home layout, and writes a
loadable Ed25519 keypair; a second init refuses (exit 1) and leaves both PEMs
byte-identical (the destructive-regeneration guard); --force regenerates (new
private key bytes); $SENTINEL_HOME steers a no-flag run.
"""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinel_slice import apphome
from sentinel_slice.init_app import main


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def test_fresh_init_creates_layout_and_loadable_keypair(tmp_path):
    home = str(tmp_path / "home")
    lines = []

    rc = main(["--home", home], print_fn=lines.append)

    assert rc == 0
    # Exactly the layout — and no ledger yet (created on first order).
    assert sorted(os.listdir(home)) == ["capabilities_custom", "keys", "window"]
    assert sorted(os.listdir(apphome.keys_dir(home))) == [
        "cashier_ed25519_private.pem", "cashier_ed25519_public.pem"]
    priv = serialization.load_pem_private_key(
        _read(apphome.private_key_path(home)), password=None)
    pub = serialization.load_pem_public_key(
        _read(apphome.public_key_path(home)))
    assert isinstance(priv, Ed25519PrivateKey)
    assert isinstance(pub, Ed25519PublicKey)
    # The public PEM on disk IS this private key's public half.
    assert pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    assert apphome.is_initialized(home) is True
    assert lines[0] == "initialized " + home


def test_second_init_refuses_and_changes_nothing(tmp_path):
    home = str(tmp_path / "home")
    assert main(["--home", home], print_fn=lambda *_: None) == 0
    priv_before = _read(apphome.private_key_path(home))
    pub_before = _read(apphome.public_key_path(home))
    lines = []

    rc = main(["--home", home], print_fn=lines.append)

    assert rc == 1
    assert _read(apphome.private_key_path(home)) == priv_before
    assert _read(apphome.public_key_path(home)) == pub_before
    assert lines[0] == "already initialized: " + home


def test_force_regenerates_the_keypair(tmp_path):
    home = str(tmp_path / "home")
    assert main(["--home", home], print_fn=lambda *_: None) == 0
    priv_before = _read(apphome.private_key_path(home))
    lines = []

    rc = main(["--home", home, "--force"], print_fn=lines.append)

    assert rc == 0
    assert _read(apphome.private_key_path(home)) != priv_before
    assert lines[0].startswith("WARNING: overwriting the cashier keypair")


def test_sentinel_home_env_steers_a_flagless_run(tmp_path):
    home = str(tmp_path / "envhome")

    rc = main([], print_fn=lambda *_: None,
              environ={"SENTINEL_HOME": home})

    assert rc == 0
    assert apphome.is_initialized(home) is True
