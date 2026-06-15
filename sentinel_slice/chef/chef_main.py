# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Chef subprocess entrypoint — STANDALONE.

This module is intentionally STANDALONE: it imports nothing from the
`sentinel_slice` package (same rule as `verify_ledger.py`). It re-implements
`canonical_bytes` inline so it can verify the cashier's Ed25519 signature using
only stdlib + cryptography.

SECURITY ORDERING (critical): the cashier signature on stdin is verified BEFORE
any side effect. On a bad/forged signature the chef exits nonzero having touched
NOTHING: it does not read the fixture, does not create the out_dir, does not
write a draft.

Import closure must contain NONE of socket/http/urllib/requests (AT07). We use
`os.path` (network-free) rather than pathlib for the traversal guard.

CLI / argv (see contract §1a):
    chef_main.py <pubkey_pem_path> <fixtures_root> <out_dir>

stdin: a single JSON object — the ticket (see contract §1b).

Exit codes (contract §1d):
    0  success: output written to <out_dir>/output.txt
    2  usage error (argc, unparseable/invalid stdin JSON, missing pubkey file)
    3  signature verification failed (bad/forged/wrong-key sig)
    4  scope/path-traversal violation OR fixture file missing
    5  no handler for the capability_id (v0.5; a contract breach — the cashier
       should never mint a ticket for a capability the chef can't execute)
"""

import sys
import os
import json
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def canonical_bytes(obj) -> bytes:
    """Byte-identical to spine.canonical.canonical_bytes (re-implemented inline)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


REQUIRED_KEYS = (
    "ticket_id",
    "order_id",
    "capability_id",
    "behavior",
    "behavior_config",
    "scoped_args",
    "issued_ts",
    "cashier_sig",
)


def main(argv) -> int:
    # 1. argc — exactly 3 args after argv[0].
    if len(argv) != 4:
        print("usage: chef_main.py <pubkey_pem> <fixtures_root> <out_dir>", file=sys.stderr)
        return 2

    pubkey_path = argv[1]
    fixtures_root_arg = argv[2]
    out_dir = argv[3]

    # 2. Read + parse stdin (no fixture read, no out_dir creation yet).
    raw_stdin = sys.stdin.read()
    if not raw_stdin:
        print("empty stdin", file=sys.stderr)
        return 2
    try:
        t = json.loads(raw_stdin)
    except json.JSONDecodeError:
        print("unparseable stdin json", file=sys.stderr)
        return 2

    if not isinstance(t, dict):
        print("stdin json is not an object", file=sys.stderr)
        return 2
    for key in REQUIRED_KEYS:
        if key not in t:
            print("missing required key: {}".format(key), file=sys.stderr)
            return 2
    for key in ("ticket_id", "order_id", "capability_id", "behavior",
                "issued_ts", "cashier_sig"):
        if not isinstance(t[key], str):
            print("required key not a string: {}".format(key), file=sys.stderr)
            return 2
    if not isinstance(t["behavior_config"], dict):
        print("behavior_config is not an object", file=sys.stderr)
        return 2
    scoped_args = t["scoped_args"]
    # The cashier narrows scope to EXACTLY ONE resource, under the
    # capability's own key (thread_id / doc_id / ...). The chef is
    # key-name-agnostic: it requires one string value and reads that.
    if not isinstance(scoped_args, dict):
        print("scoped_args is not an object", file=sys.stderr)
        return 2
    scoped_values = [v for v in scoped_args.values() if isinstance(v, str)]
    if len(scoped_args) != 1 or len(scoped_values) != 1:
        print("scoped_args must hold exactly one string resource", file=sys.stderr)
        return 2

    # 3. Load pubkey + VERIFY SIGNATURE. This is the security gate; it MUST
    #    precede every side effect (no fixture read, no out_dir creation above).
    if not os.path.isfile(pubkey_path):
        print("pubkey file not found", file=sys.stderr)
        return 2
    with open(pubkey_path, "rb") as fh:
        pem_bytes = fh.read()
    try:
        public_key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError):
        print("pubkey file is not a valid PEM public key", file=sys.stderr)
        return 2
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        print("pubkey is not an Ed25519 public key", file=sys.stderr)
        return 2

    signable = {
        "ticket_id": t["ticket_id"],
        "order_id": t["order_id"],
        "capability_id": t["capability_id"],
        "behavior": t["behavior"],
        "behavior_config": t["behavior_config"],
        "scoped_args": t["scoped_args"],
        "issued_ts": t["issued_ts"],
    }
    try:
        sig = base64.b64decode(t["cashier_sig"], validate=True)
    except (ValueError, TypeError):
        # Malformed base64 signature is a signature failure.
        print("signature verification failed", file=sys.stderr)
        return 3
    try:
        public_key.verify(sig, canonical_bytes(signable))
    except InvalidSignature:
        print("signature verification failed", file=sys.stderr)
        return 3
    # NOTHING has been read from the kitchen and out_dir does NOT exist yet.

    # 4. Resolve the scoped resource -> fixture path, with traversal guard.
    resource = scoped_values[0]
    if "/" not in resource:
        print("path traversal rejected", file=sys.stderr)
        return 4
    owner, local = resource.split("/", 1)
    if owner == "" or local == "":
        print("path traversal rejected", file=sys.stderr)
        return 4
    # local must be a SINGLE safe path component (no separator, no parent ref).
    # Defense in depth with the cashier scope check: confine the read to the
    # owner's OWN mailbox subdir so a crafted thread_id cannot cross tenants.
    if "/" in local or "\\" in local or local in (".", ".."):
        print("path traversal rejected", file=sys.stderr)
        return 4
    # Reject control characters (NUL, newline, ...) independently of the cashier:
    # the chef is the standalone last line, so it must not depend on open() to
    # raise on a path-truncating NUL byte.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in resource):
        print("path traversal rejected", file=sys.stderr)
        return 4

    fixtures_root = os.path.realpath(fixtures_root_arg)
    owner_dir = os.path.realpath(os.path.join(fixtures_root, owner))
    candidate = os.path.realpath(os.path.join(owner_dir, local + ".txt"))
    try:
        common = os.path.commonpath([owner_dir, candidate])
    except ValueError:
        # Different drive on Windows, etc.
        print("path traversal rejected", file=sys.stderr)
        return 4
    if common != owner_dir or candidate == owner_dir:
        print("path traversal rejected", file=sys.stderr)
        return 4

    # 5. Read ONLY that file (the only read; no network, no other reads).
    if not os.path.isfile(candidate):
        print("fixture not found", file=sys.stderr)
        return 4
    with open(candidate, "r", encoding="utf-8") as fh:
        source_text = fh.read()

    # 6. Dispatch on the signed BEHAVIOR (the code template) to its
    #    DETERMINISTIC transform. A capability is a configured instance of a
    #    behavior; many capabilities can share one behavior. New BEHAVIORS need
    #    a handler here (engineer work); new CAPABILITIES are pure config.
    #    No LLM anywhere — every transform is a pure, auditable function.
    handler = _HANDLERS.get(t["behavior"])
    if handler is None:
        print("no handler for behavior {}".format(t["behavior"]),
              file=sys.stderr)
        return 5
    output_text = handler(resource, source_text, t["behavior_config"])

    # 7. Create out_dir, write the single output artifact (success-only side
    #    effect). The filename is the same for every capability. Skip makedirs
    #    when the dir already exists: under an OS sandbox (AppContainer) the
    #    chef may be denied STAT on out_dir's parents, and makedirs(exist_ok)
    #    walks the parent chain regardless — so a pre-created, granted out_dir
    #    must not trigger that walk. isdir(out_dir) succeeds (it IS granted).
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    output_file = os.path.join(out_dir, "output.txt")
    with open(output_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(output_text)

    # 8. Success.
    return 0


# ---------------------------------------------------------------------------
# Capability handlers — each a PURE (resource_id, source_text) -> output_text
# transform. Deterministic, no model, no network. This dispatch table is the
# extension point: a new capability adds one entry here, one descriptor JSON,
# and one policy grant — nothing in the cashier/ledger/chef plumbing changes.
# ---------------------------------------------------------------------------

def _safe_fields(resource, source_text):
    """The safe, fixed set of values a TEXT behavior may reference, all derived
    from the one scoped resource the chef read — no globals, no secrets."""
    lines = source_text.splitlines()
    subject = ""
    for line in lines:
        if line.startswith("Subject:"):
            subject = line[len("Subject:"):].strip()
            break
    first = next((ln.strip() for ln in lines if ln.strip()), "")
    return {
        "resource": resource,
        "subject": subject,
        "first_line": first,
        "line_count": str(len(lines)),
        "word_count": str(len(source_text.split())),
        "body": source_text,
    }


def _handle_draft_reply(resource, source_text, config):
    """Draft a reply to an email thread (the original capability; output is
    byte-identical to v0.1 so existing receipts/tests are unchanged)."""
    subject = "(no subject)"
    for line in source_text.splitlines():
        if line.startswith("Subject:"):
            subject = line[len("Subject:"):].strip()
            break
    return (
        "Re: {}\n\n"
        "Thank you for your message. A draft reply has been prepared for your review.\n\n"
        "-- Sentinel Loop draft (no send performed)\n"
    ).format(subject)


def _handle_docs_summarize(resource, source_text, config):
    """Extractive (NO MODEL) summary of a document: its first non-empty line
    plus deterministic size stats. Demonstrates 'read scoped data, return a
    derived artifact' — and the content still never touches the ledger."""
    lines = source_text.splitlines()
    first = next((ln.strip() for ln in lines if ln.strip()), "(empty document)")
    n_lines = len(lines)
    n_words = len(source_text.split())
    return (
        "Summary of {}\n\n"
        "Opening: {}\n"
        "Length: {} lines, {} words.\n\n"
        "-- Sentinel Loop summary (extractive, no model)\n"
    ).format(resource, first, n_lines, n_words)


def _handle_payment_initiate(resource, source_text, config):
    """Produce a payment-authorization REQUEST artifact. The slice NEVER moves
    money; this is a reviewable request only (high-risk capability, gated by
    second-admin in the console and user-confirmation in consumer mode)."""
    return (
        "PAYMENT REQUEST — NO FUNDS MOVED\n\n"
        "Regarding: {}\n"
        "This is a request artifact for human authorization. The Sentinel Loop "
        "slice does not execute payments.\n\n"
        "-- Sentinel Loop (no side effect performed)\n"
    ).format(resource)


# Keyed by BEHAVIOR (the code template), not by capability id — so an operator
# can create many menu items (capabilities) that reuse one behavior with no new
# code. These behavior names are the contract shared with the catalog/templates.
def _handle_template(resource, source_text, config):
    """GENERIC TEXT BEHAVIOR — the one an operator authors as DATA, no code.

    Renders config['template'] with $-placeholders against the safe fixed field
    set ($resource $subject $first_line $line_count $word_count $body) via
    string.Template.safe_substitute. string.Template is chosen precisely
    because it permits ONLY simple $name substitution — no attribute access, no
    indexing, no code — so an operator-written template can do nothing but fill
    in text. The output is text in the serving window; it cannot send, call
    out, or reach anything beyond the resource the chef already read."""
    import string

    template_str = config.get("template")
    if not isinstance(template_str, str) or not template_str:
        raise ValueError("template behavior requires a non-empty config.template")
    return string.Template(template_str).safe_substitute(
        _safe_fields(resource, source_text))


_HANDLERS = {
    "draft_reply": _handle_draft_reply,
    "docs_summarize": _handle_docs_summarize,
    "payment_request": _handle_payment_initiate,
    "template": _handle_template,
}


if __name__ == "__main__":
    sys.exit(main(sys.argv))
