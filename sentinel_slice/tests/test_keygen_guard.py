"""Keygen overwrite protection.

Regenerating the cashier keypair breaks verification of every ledger signed
by the old key, so `keygen.main` must refuse to overwrite an existing pair
unless forced — and must leave the existing PEM bytes untouched when it
refuses. Asserted on exact exit codes and exact file bytes.
"""

import os

from cryptography.hazmat.primitives import serialization

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


def test_keygen_fresh_clone_generates_when_only_public_present(tmp_path, monkeypatch, capsys):
    """The OSS fresh-clone state: a committed public key, no private key.
    keygen must JUST WORK (no --force needed) and create the missing private
    key, since nothing irreplaceable is at risk."""
    keys_dir = tmp_path / "keys"
    _point_keygen_at(monkeypatch, keys_dir)

    # Produce the fresh-clone state: public present, private absent.
    assert keygen.main([]) == 0
    (keys_dir / "cashier_ed25519_private.pem").unlink()
    assert (keys_dir / "cashier_ed25519_public.pem").is_file()
    assert not (keys_dir / "cashier_ed25519_private.pem").exists()
    capsys.readouterr()  # clear

    # No --force, yet it generates and explains why.
    assert keygen.main([]) == 0
    out = capsys.readouterr().out
    assert "no private key" in out
    assert (keys_dir / "cashier_ed25519_private.pem").is_file()


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


def _public_bytes_of_private(path):
    priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _public_bytes_of_public(path):
    pub = serialization.load_pem_public_key(path.read_bytes())
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_keygen_writes_into_explicit_keys_dir(tmp_path, monkeypatch):
    """--keys DIR writes the pair into DIR (not the committed dir), and the two
    PEMs are a matching Ed25519 pair."""
    # Point the DEFAULT at one place; aim the flag at another. The flag must win.
    default_dir = tmp_path / "committed"
    _point_keygen_at(monkeypatch, default_dir)
    target = tmp_path / "elsewhere" / "keys"

    assert keygen.main(["--keys", str(target)]) == 0

    priv_pem = target / "cashier_ed25519_private.pem"
    pub_pem = target / "cashier_ed25519_public.pem"
    assert priv_pem.is_file() and pub_pem.is_file()
    # The pair matches: the private key's public half equals the public PEM.
    assert _public_bytes_of_private(priv_pem) == _public_bytes_of_public(pub_pem)
    # The default/committed dir was never created.
    assert not default_dir.exists()


def test_keys_flag_with_force_does_not_touch_default_dir(tmp_path, monkeypatch, capsys):
    """The exact regression: `--force` aimed at an explicit --keys dir must
    regenerate ONLY that dir and leave the default (committed) keypair's bytes
    byte-for-byte intact."""
    default_dir = tmp_path / "committed"
    _point_keygen_at(monkeypatch, default_dir)

    # Seed the default/committed dir with a keypair, capture its exact bytes.
    assert keygen.main([]) == 0
    committed_priv = (default_dir / "cashier_ed25519_private.pem").read_bytes()
    committed_pub = (default_dir / "cashier_ed25519_public.pem").read_bytes()
    capsys.readouterr()

    # Force-regenerate into a DIFFERENT dir. Seed it first so --force is needed.
    other = tmp_path / "other" / "keys"
    assert keygen.main(["--keys", str(other)]) == 0
    other_priv_before = (other / "cashier_ed25519_private.pem").read_bytes()
    assert keygen.main(["--keys", str(other), "--force"]) == 0
    warn = capsys.readouterr().out
    assert "WARNING: overwriting the cashier keypair at {}".format(
        os.path.abspath(str(other))) in warn

    # The committed dir is untouched, byte-for-byte.
    assert (default_dir / "cashier_ed25519_private.pem").read_bytes() == committed_priv
    assert (default_dir / "cashier_ed25519_public.pem").read_bytes() == committed_pub
    # The targeted dir really got a new key.
    assert (other / "cashier_ed25519_private.pem").read_bytes() != other_priv_before


def test_keygen_refuses_overwrite_in_explicit_keys_dir(tmp_path, monkeypatch, capsys):
    """The overwrite guard follows the --keys dir, not the module default."""
    default_dir = tmp_path / "committed"
    _point_keygen_at(monkeypatch, default_dir)
    target = tmp_path / "target" / "keys"

    assert keygen.main(["--keys", str(target)]) == 0
    priv_before = (target / "cashier_ed25519_private.pem").read_bytes()
    capsys.readouterr()

    assert keygen.main(["--keys", str(target)]) == 1
    out = capsys.readouterr().out
    assert "refusing to overwrite existing keypair" in out
    # It named the TARGET dir's paths, and left them byte-identical.
    assert os.path.join(os.path.abspath(str(target)), "cashier_ed25519_private.pem") in out
    assert (target / "cashier_ed25519_private.pem").read_bytes() == priv_before
