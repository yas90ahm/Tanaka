"""Console identity — REAL Ed25519 signed-request auth (unit level).

Pins the actual crypto: a valid signature authenticates to the right Admin;
the wrong key, a tampered method/path/body, a stale/future timestamp, an
unknown id, or a missing header all FAIL (return None -> 401). Also pins the
exact signed-bytes wire format, which the browser (WebCrypto) must reproduce.
"""

import hashlib

from sentinel_slice.console import signed_auth
from sentinel_slice.console.auth import Admin, ROLE_AUTHOR


def _registry():
    reg, signers = signed_auth.dev_registry()
    return reg, signers


def _hdr(d):
    return lambda name: d.get(name)


def test_signing_bytes_exact_wire_format():
    body = b"hello"
    digest = hashlib.sha256(body).hexdigest()
    expected = (
        "sentinel-console-auth-1\nPOST\n/api/x\ntanaka\n1700000000\n" + digest
    ).encode("utf-8")
    assert signed_auth.signing_bytes("POST", "/api/x", "tanaka", 1700000000, body) == expected
    # method is upper-cased into the signed string (client/server agree).
    assert signed_auth.signing_bytes("post", "/api/x", "tanaka", 1700000000, body) == expected
    # empty body (GET) digests the empty string.
    assert hashlib.sha256(b"").hexdigest() in signed_auth.signing_bytes(
        "GET", "/p", "a", 1, b"").decode("utf-8")


def test_valid_signature_authenticates_to_admin():
    reg, signers = _registry()
    headers = signed_auth.sign_headers(
        signers["tanaka"], admin_id="tanaka", method="GET",
        path="/api/capabilities", body=b"", now=1000)
    admin = signed_auth.verify(
        reg, method="GET", path="/api/capabilities", body=b"",
        header=_hdr(headers), now=1000)
    assert admin == Admin(id="tanaka", role=ROLE_AUTHOR)


def test_wrong_key_is_rejected():
    reg, _signers = _registry()
    outsider, _ = signed_auth.generate_admin("author")
    headers = signed_auth.sign_headers(
        outsider, admin_id="tanaka", method="GET", path="/p", body=b"", now=5)
    assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                              header=_hdr(headers), now=5) is None


def test_unknown_id_is_rejected():
    reg, _signers = _registry()
    ghost, _ = signed_auth.generate_admin("author")
    headers = signed_auth.sign_headers(
        ghost, admin_id="ghost", method="GET", path="/p", body=b"", now=5)
    assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                              header=_hdr(headers), now=5) is None


def test_tampered_body_method_and_path_are_rejected():
    reg, signers = _registry()
    headers = signed_auth.sign_headers(
        signers["tanaka"], admin_id="tanaka", method="POST",
        path="/api/policies/publish", body=b'{"a":1}', now=10)
    # tampered body
    assert signed_auth.verify(reg, method="POST", path="/api/policies/publish",
                              body=b'{"a":2}', header=_hdr(headers), now=10) is None
    # tampered method
    assert signed_auth.verify(reg, method="GET", path="/api/policies/publish",
                              body=b'{"a":1}', header=_hdr(headers), now=10) is None
    # tampered path
    assert signed_auth.verify(reg, method="POST", path="/api/policies/rollback",
                              body=b'{"a":1}', header=_hdr(headers), now=10) is None
    # untouched -> accepts
    assert signed_auth.verify(reg, method="POST", path="/api/policies/publish",
                              body=b'{"a":1}', header=_hdr(headers), now=10) is not None


def test_stale_and_future_timestamps_are_rejected():
    reg, signers = _registry()
    headers = signed_auth.sign_headers(
        signers["tanaka"], admin_id="tanaka", method="GET", path="/p",
        body=b"", now=1000)
    skew = signed_auth.DEFAULT_MAX_SKEW_SECONDS
    # within the window: ok
    assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                              header=_hdr(headers), now=1000 + skew) is not None
    # too old
    assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                              header=_hdr(headers), now=1000 + skew + 1) is None
    # too far in the future
    assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                              header=_hdr(headers), now=1000 - skew - 1) is None


def test_missing_headers_are_rejected():
    reg, signers = _registry()
    full = signed_auth.sign_headers(
        signers["tanaka"], admin_id="tanaka", method="GET", path="/p",
        body=b"", now=5)
    for drop in (signed_auth.H_ID, signed_auth.H_TS, signed_auth.H_SIG):
        partial = {k: v for k, v in full.items() if k != drop}
        assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                                  header=_hdr(partial), now=5) is None
    # no headers at all
    assert signed_auth.verify(reg, method="GET", path="/p", body=b"",
                              header=_hdr({}), now=5) is None


def test_registry_from_file_roundtrips(tmp_path):
    import json

    priv, entry = signed_auth.generate_admin("reviewer")
    cfg = tmp_path / "admins.json"
    cfg.write_text(json.dumps({"admins": {"rao": {
        "pubkey_pem": signed_auth.public_pem(entry.public_key),
        "role": "reviewer"}}}), encoding="utf-8")
    reg = signed_auth.KeyRegistry.from_file(str(cfg))
    assert reg.ids() == ["rao"]
    headers = signed_auth.sign_headers(
        priv, admin_id="rao", method="GET", path="/p", body=b"", now=7)
    admin = signed_auth.verify(reg, method="GET", path="/p", body=b"",
                               header=_hdr(headers), now=7)
    assert admin == Admin(id="rao", role="reviewer")
