"""Host-side helper for the microVM proof: generate a real signed ticket + the
cashier public key + the fixture the chef will read, into an I/O directory the
VM mounts. The chef inside the VM verifies this signature before doing anything,
exactly as in production — so the proof exercises the real trust gate, not a
stub.

Usage: python microvm/make_order.py <io_dir> <fixture_src>
"""

import base64
import json
import os
import shutil
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.spine.canonical import canonical_bytes

io_dir, fixture_src = sys.argv[1], sys.argv[2]
os.makedirs(io_dir, exist_ok=True)

priv = Ed25519PrivateKey.generate()
with open(os.path.join(io_dir, "pub.pem"), "wb") as fh:
    fh.write(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))

# The exact 7-key signable the chef reconstructs and verifies.
signable = {
    "ticket_id": "tkt-microvm",
    "order_id": "ord-microvm",
    "capability_id": "cap.email.draft_reply.v1",
    "behavior": "draft_reply",
    "behavior_config": {},
    "scoped_args": {"thread_id": "user.kenji/t-001"},
    "issued_ts": "2026-06-14T00:00:00+00:00",
}
sig = priv.sign(canonical_bytes(signable))
wire = dict(signable, cashier_sig=base64.b64encode(sig).decode("ascii"))
with open(os.path.join(io_dir, "ticket.json"), "w", encoding="utf-8") as fh:
    json.dump(wire, fh)

# The kitchen fixture the chef will read (the committed t-001 mailbox file).
dst = os.path.join(io_dir, "fixtures", "user.kenji")
os.makedirs(dst, exist_ok=True)
shutil.copyfile(fixture_src, os.path.join(dst, "t-001.txt"))

os.makedirs(os.path.join(io_dir, "out"), exist_ok=True)
print("wrote pub.pem, ticket.json, fixtures/user.kenji/t-001.txt, out/ into", io_dir)
