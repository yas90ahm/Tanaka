# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Console identity — REAL Ed25519 request authentication (replaces the mock
static-token table).

An admin holds an Ed25519 PRIVATE key. Every request carries three headers:
the admin id, a unix timestamp, and an Ed25519 signature over a canonical
`(scheme, method, path, id, ts, sha256(body))` string. The server holds only
PUBLIC keys (a `KeyRegistry`) and verifies the signature. So:

  - possession of the private key is PROVEN on every request (no shared secret
    is ever transmitted or stored),
  - the method + path + body are integrity-bound (a tampered request fails),
  - a stale request (timestamp outside a freshness window) is rejected.

This changes only the IDENTITY SOURCE. Separation of duties (author vs
reviewer; "cannot approve your own change") is unchanged and still enforced in
service.py on the resolved `Admin`. Federating these keys to a directory
(SSO/OIDC) is a deployment concern behind the same `KeyRegistry` seam — the
cryptographic proof-of-possession here is real, not mocked.

Replay is bounded to the skew window; a single-use nonce cache would tighten it
further (noted, not built — the console is a single-threaded localhost tool).
"""

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinel_slice.console.auth import Admin, ROLES

# Domain-separation prefix; bump if the signed-string format ever changes.
SCHEME = "sentinel-console-auth-1"
# Reject a signature whose timestamp is more than this many seconds from now.
DEFAULT_MAX_SKEW_SECONDS = 300

H_ID = "X-Admin-Id"
H_TS = "X-Admin-Timestamp"
H_SIG = "X-Admin-Signature"


def signing_bytes(method: str, path: str, admin_id: str, ts, body: bytes) -> bytes:
    """The exact bytes signed and verified. Newline-delimited and ASCII-only by
    construction so a browser (WebCrypto) and Python produce IDENTICAL bytes.
    `body` is the raw request body (b'' for GET)."""
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join(
        [SCHEME, method.upper(), path, admin_id, str(ts), digest]
    ).encode("utf-8")


@dataclass(frozen=True)
class KeyEntry:
    public_key: Ed25519PublicKey
    role: str


class KeyRegistry:
    """admin_id -> (Ed25519 public key, role). Holds NO private keys."""

    def __init__(self, by_id: dict) -> None:
        self._by_id = dict(by_id)

    def get(self, admin_id):
        return self._by_id.get(admin_id)

    def ids(self):
        return sorted(self._by_id)

    @classmethod
    def from_file(cls, path: str) -> "KeyRegistry":
        """Load {"admins": {"<id>": {"pubkey_pem": "...", "role": "..."}}}."""
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        by_id = {}
        for admin_id, who in obj["admins"].items():
            if who["role"] not in ROLES:
                raise ValueError(
                    "admin {!r} has invalid role {!r}".format(admin_id, who["role"]))
            pub = serialization.load_pem_public_key(who["pubkey_pem"].encode("utf-8"))
            if not isinstance(pub, Ed25519PublicKey):
                raise ValueError("admin {!r} key is not Ed25519".format(admin_id))
            by_id[admin_id] = KeyEntry(public_key=pub, role=who["role"])
        return cls(by_id)


def public_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def sign_headers(private_key, *, admin_id, method, path, body=b"", now) -> dict:
    """Client-side: the three identity headers for one request. `now` is unix
    seconds. `body` must be the EXACT raw bytes that will be sent."""
    ts = int(now)
    sig = private_key.sign(signing_bytes(method, path, admin_id, ts, body))
    return {
        H_ID: admin_id,
        H_TS: str(ts),
        H_SIG: base64.b64encode(sig).decode("ascii"),
    }


def verify(registry, *, method, path, body, header, now,
           max_skew_seconds=DEFAULT_MAX_SKEW_SECONDS):
    """Server-side: return the authenticated `Admin`, or `None` (=> 401).

    None on ANY of: a missing header, an unknown admin id, a non-integer or
    stale timestamp, or an invalid signature. `header` is a callable
    name -> str|None (e.g. `self.headers.get`)."""
    admin_id = header(H_ID)
    ts_raw = header(H_TS)
    sig_b64 = header(H_SIG)
    if not (admin_id and ts_raw and sig_b64):
        return None
    entry = registry.get(admin_id)
    if entry is None:
        return None
    try:
        ts = int(ts_raw)
    except (TypeError, ValueError):
        return None
    if abs(int(now) - ts) > max_skew_seconds:
        return None
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError):
        return None
    try:
        entry.public_key.verify(
            sig, signing_bytes(method, path, admin_id, ts, body))
    except InvalidSignature:
        return None
    return Admin(id=admin_id, role=entry.role)


def generate_admin(role: str):
    """Mint a fresh admin keypair: returns (private_key, KeyEntry)."""
    priv = Ed25519PrivateKey.generate()
    return priv, KeyEntry(public_key=priv.public_key(), role=role)


def dev_registry():
    """A REAL (not mock) two-admin registry with freshly generated keypairs:
    one author (`tanaka`), one reviewer (`reviewer-rao`). Returns
    (KeyRegistry, {admin_id: private_key}). The PRIVATE keys are handed back to
    the caller (tests / a local bootstrap); the registry holds only public
    keys."""
    a_priv, a_entry = generate_admin("author")
    r_priv, r_entry = generate_admin("reviewer")
    reg = KeyRegistry({"tanaka": a_entry, "reviewer-rao": r_entry})
    return reg, {"tanaka": a_priv, "reviewer-rao": r_priv}
