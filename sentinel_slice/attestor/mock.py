# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""
==============================  MOCK ATTESTOR  ==============================
!!! THIS IS A MOCK. IT IS *NOT* A REAL TEE / HARDWARE ATTESTATION. !!!

`MockAttestor` does NOT produce a genuine remote-attestation quote. It merely
signs a hash of the chef's code (the "measurement") with a throwaway Ed25519
key generated per-instance, as a stand-in to populate the receipt's
`attestation` slot. EVERY artifact it emits is loudly labeled `"mock": true`
and carries a MOCK note. See SPEC's "Explicitly mocked" section and PROGRESS.md.

A real attestor would bind the measurement to hardware-rooted evidence; this
one proves NOTHING about the execution environment. Do not trust it.
============================================================================
"""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class MockAttestor:
    """MOCK attestor — NOT a real TEE. Signs a hash of the chef's code as a
    stand-in 'measurement'. Every artifact is labeled mock. See SPEC
    'Explicitly mocked'."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        # Generate a dedicated MockAttestor Ed25519 key if none supplied.
        # This key is DISTINCT from the cashier/ledger key by construction.
        # It is deterministic-per-instance (held for the life of the object).
        self._key = private_key if private_key is not None else Ed25519PrivateKey.generate()

    def quote(self, measurement_hex: str) -> dict:
        """Return a MOCK attestation dict over `measurement_hex`.

        All values are JSON-plain (str/bool) so the dict can be hashed into
        the receipt content via canonical JSON without error. `"mock"` is the
        literal Python `True` (serializes to JSON `true`)."""
        sig = base64.b64encode(
            self._key.sign(measurement_hex.encode("utf-8"))
        ).decode("ascii")
        return {
            "mock": True,
            "attestor": "MockAttestor",
            "measurement": measurement_hex,
            "sig": sig,
            "note": (
                "MOCK ATTESTATION — signs a code hash, NOT a TEE quote. "
                "Proves the receipt attestation slot only."
            ),
        }

    def public_pem(self) -> bytes:
        """Expose the per-instance public key (SubjectPublicKeyInfo PEM) so a
        future test could verify the MOCK signature. No current test requires
        it."""
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
