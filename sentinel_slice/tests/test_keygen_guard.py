"""Keygen overwrite protection.

Regenerating the cashier keypair breaks verification of every ledger signed
by the old key, so `keygen.main` must refuse to overwrite an existing pair
unless forced — and must leave the existing PEM bytes untouched when it
refuses. Asserted on exact exit codes and exact file bytes.
"""

import os

from sentinel_slice import keygen


def _point_keygen_at(monkeypatch, keys_dir):
    monkeypatch.setattr(keygen, "KEYS_DIR", str(keys_dir))
    monkeypatch.setattr(
        keygen, "PRIVATE_KEY_PATH", os.path.join(str(keys_dir), "cashier_ed25519_private.pem")
    )
    monkeypatch.setattr(
        keygen, "PUBLIC_KEY_PATH", os.path.join(str(keys_dir), "cashier_ed25519_public.pem")
    )


def test_keygen_refuses_overwrite_without_force(tmp_path, monkeypatch, capsys):
    keys_dir = tmp_path / "keys"
    _point_keygen_at(monkeypatch, keys_dir)

    assert keygen.main([]) == 0
    priv_before = (keys_dir / "cashier_ed25519_private.pem").read_bytes()
    pub_before = (keys_dir / "cashier_ed25519_public.pem").read_bytes()

    assert keygen.main([]) == 1
    out = capsys.readouterr().out
    assert "refusing to overwrite existing keypair" in out

    # The refusal left both PEMs byte-identical.
    assert (keys_dir / "cashier_ed25519_private.pem").read_bytes() == priv_before
    assert (keys_dir / "cashier_ed25519_public.pem").read_bytes() == pub_before


def test_keygen_force_overwrites_with_warning(tmp_path, monkeypatch, capsys):
    keys_dir = tmp_path / "keys"
    _point_keygen_at(monkeypatch, keys_dir)

    assert keygen.main([]) == 0
    priv_before = (keys_dir / "cashier_ed25519_private.pem").read_bytes()

    assert keygen.main(["--force"]) == 0
    out = capsys.readouterr().out
    assert "WARNING: overwriting the cashier keypair" in out

    # A genuinely new key was written.
    assert (keys_dir / "cashier_ed25519_private.pem").read_bytes() != priv_before
