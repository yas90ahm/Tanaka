"""Inspector - the back office.

Essay 3: "The receipts go to two places. One copy goes to the diner. One copy
goes to the back office, where the inspector watches patterns across all the
orders the restaurant served today. The cashier handles one order at a time;
the inspector sees the whole day."

This module is that inspector, in miniature. It is READ-ONLY over the ledger
(SELECT only - it could not tamper if it wanted to), it validates the chain
before it trusts a single row, and it renders what it finds in plain English
for an operator - Tanaka - not a log dump for an engineer.

Structural privacy holds here too: receipts carry digests and metadata, never
payload content, so the inspector is structurally incapable of leaking the
data it watches. It sees WHO ordered WHAT, WHEN, and what the governance
layer decided - never the meal.

Findings are DETERMINISTIC RULES over the chain (no LLM, no scoring model):
every off-menu attempt is a possible prompt injection; every replay is a
possible replay attack; and so on. Severity is fixed per rule.

LOUD FLAGS (honest disclosure):
- This is pattern SURFACING, not anomaly DETECTION. There is no baseline, no
  time-windowing, no behavioral model - those are the real system's anomaly
  dashboard, still a STUB.
- All audit is retrospective (Essay 5): the inspector finds attacks AFTER the
  receipts exist. It limits blast radius and accelerates detection; it does
  not prevent.
- Rows written before v0.2 carry no order_meta; the inspector counts them
  separately rather than guessing.

CLI:  python -m sentinel_slice.inspector <ledger.db> [--pubkey PEM] [--json]
Exit: 0 chain valid (findings or not), 1 chain broken/tampered, 2 usage.
"""

import argparse
import base64
import hashlib
import json
import sqlite3
import sys

from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.hashing import GENESIS_PREV_HASH

# Reason codes the cashier/runner can emit, with the inspector's fixed rule
# for each: (severity, finding code, operator-facing explanation).
REASON_RULES = {
    "OFF_MENU": (
        "high",
        "OFF_MENU_ATTEMPTS",
        "order(s) for capabilities not on the menu - the signature of a "
        "prompt-injected or misbehaving agent. The cashier refused before "
        "any execution.",
    ),
    "REPLAY": (
        "high",
        "REPLAY_ATTEMPTS",
        "order(s) reusing an already-spent nonce - possible replay attack "
        "or a badly looping agent.",
    ),
    "OUT_OF_SCOPE": (
        "medium",
        "SCOPE_VIOLATIONS",
        "order(s) reaching for data outside the principal's own scope - "
        "possible cross-tenant probing.",
    ),
    "ROLE_NOT_PERMITTED": (
        "medium",
        "ROLE_VIOLATIONS",
        "order(s) from roles the policy does not permit - possible "
        "privilege escalation attempt or a policy gap.",
    ),
    "RATE_LIMITED": (
        "low",
        "RATE_PRESSURE",
        "order(s) rejected by the rate limit - an agent running hot, or a "
        "limit set too tight for legitimate traffic.",
    ),
    "EXECUTION_FAILED": (
        "medium",
        "EXECUTION_FAILURES",
        "authorized order(s) whose chef failed to produce a result - "
        "investigate the kitchen, not the diner.",
    ),
}


def read_rows(db_path: str) -> list[tuple[int, dict]]:
    """SELECT every (seq, parsed row) in seq order. Read-only by construction:
    this module issues no other SQL. Raises sqlite3.OperationalError on a
    missing/invalid db and ValueError on an unparseable row."""
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT seq, json FROM receipts ORDER BY seq ASC")
        fetched = cur.fetchall()
    finally:
        conn.close()
    rows = []
    for seq, raw in fetched:
        rows.append((seq, json.loads(raw)))
    return rows


def check_chain(rows, public_key=None):
    """Walk the chain exactly like the standalone verifier: recompute each
    row's hash over its own key set minus this_hash/sig, check linkage from
    genesis, and (when a public key is supplied) check every signature.

    Returns (chain_valid: bool, first_broken_seq: int | None,
    reason: str | None)."""
    expected_prev = GENESIS_PREV_HASH
    for seq, row in rows:
        try:
            content = {
                k: v for k, v in row.items() if k not in ("this_hash", "sig")
            }
            recomputed = hashlib.sha256(canonical_bytes(content)).hexdigest()
        except (TypeError, ValueError):
            return (False, seq, "json_parse")
        if recomputed != row.get("this_hash"):
            return (False, seq, "hash_mismatch")
        if row.get("prev_hash") != expected_prev:
            return (False, seq, "prev_hash_mismatch")
        if public_key is not None:
            try:
                public_key.verify(
                    base64.b64decode(row["sig"]), recomputed.encode("utf-8")
                )
            except Exception:
                return (False, seq, "bad_signature")
        expected_prev = row["this_hash"]
    return (True, None, None)


def build_report(rows, public_key=None) -> dict:
    """The whole day at a glance, as a JSON-plain dict. Deterministic: same
    rows in, same report out."""
    chain_valid, broken_seq, broken_reason = check_chain(rows, public_key)

    fulfilled = 0
    rejected = 0
    by_reason: dict[str, list[int]] = {}
    by_principal: dict[str, dict] = {}
    mock_attestations = 0
    legacy_rows = 0

    for seq, row in rows:
        status = row.get("status")
        if status == "FULFILLED":
            fulfilled += 1
        else:
            rejected += 1
            reason = row.get("reason_code") or "UNSPECIFIED"
            by_reason.setdefault(reason, []).append(seq)

        attestation = row.get("attestation")
        if isinstance(attestation, dict) and attestation.get("mock") is True:
            mock_attestations += 1

        meta = row.get("order_meta")
        if not isinstance(meta, dict):
            legacy_rows += 1
            continue
        principal = meta.get("principal", "(unknown)")
        entry = by_principal.setdefault(
            principal, {"orders": 0, "fulfilled": 0, "rejected": 0, "capabilities": []}
        )
        entry["orders"] += 1
        if status == "FULFILLED":
            entry["fulfilled"] += 1
        else:
            entry["rejected"] += 1
        cap = meta.get("capability_id")
        if cap and cap not in entry["capabilities"]:
            entry["capabilities"].append(cap)

    findings = []
    if not chain_valid:
        findings.append(
            {
                "severity": "critical",
                "code": "CHAIN_BROKEN",
                "message": (
                    "the receipt chain FAILS verification at seq {} "
                    "({}) - every row from there on is untrustworthy. "
                    "Preserve the db and investigate before anything else."
                ).format(broken_seq, broken_reason),
                "receipts": [broken_seq],
            }
        )
    for reason, (severity, code, explanation) in REASON_RULES.items():
        seqs = by_reason.get(reason)
        if seqs:
            findings.append(
                {
                    "severity": severity,
                    "code": code,
                    "message": "{} {}".format(len(seqs), explanation),
                    "receipts": list(seqs),
                }
            )
    unknown_reasons = sorted(set(by_reason) - set(REASON_RULES) - {"UNSPECIFIED"})
    for reason in unknown_reasons:
        findings.append(
            {
                "severity": "medium",
                "code": "UNRECOGNIZED_REASON",
                "message": "{} rejection(s) with reason code {!r} this "
                "inspector has no rule for - review manually.".format(
                    len(by_reason[reason]), reason
                ),
                "receipts": list(by_reason[reason]),
            }
        )
    if mock_attestations:
        findings.append(
            {
                "severity": "info",
                "code": "ATTESTATION_IS_MOCK",
                "message": "{} receipt(s) carry MOCK attestations - they "
                "prove the attestation slot, NOT a TEE. Do not present them "
                "to an auditor as hardware evidence.".format(mock_attestations),
                "receipts": [],
            }
        )

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_rank[f["severity"]], f["code"]))

    return {
        "receipts_total": len(rows),
        "chain_valid": chain_valid,
        "first_broken_seq": broken_seq,
        "signatures_checked": public_key is not None,
        "fulfilled": fulfilled,
        "rejected": rejected,
        "by_reason": {k: len(v) for k, v in sorted(by_reason.items())},
        "by_principal": dict(sorted(by_principal.items())),
        "legacy_rows": legacy_rows,
        "findings": findings,
    }


def render_text(report: dict) -> str:
    """Plain-English rendering for the operator. No jargon, no dump."""
    lines = []
    lines.append("INSPECTOR REPORT")
    lines.append(
        "chain: {} ({} receipt(s){})".format(
            "VALID" if report["chain_valid"] else "BROKEN",
            report["receipts_total"],
            ", signatures checked"
            if report["signatures_checked"]
            else ", signatures NOT checked - pass --pubkey",
        )
    )
    lines.append(
        "orders: {} fulfilled, {} rejected".format(
            report["fulfilled"], report["rejected"]
        )
    )
    if report["by_reason"]:
        parts = [
            "{} {}".format(count, reason)
            for reason, count in report["by_reason"].items()
        ]
        lines.append("rejections: " + ", ".join(parts))
    for principal, entry in report["by_principal"].items():
        lines.append(
            "principal {}: {} order(s), {} fulfilled, {} rejected, "
            "capabilities: {}".format(
                principal,
                entry["orders"],
                entry["fulfilled"],
                entry["rejected"],
                ", ".join(entry["capabilities"]) or "(none)",
            )
        )
    if report["legacy_rows"]:
        lines.append(
            "{} pre-v0.2 receipt(s) carry no order metadata "
            "(counted in totals, absent from per-principal lines)".format(
                report["legacy_rows"]
            )
        )
    if report["findings"]:
        lines.append("")
        lines.append("FINDINGS")
        for f in report["findings"]:
            receipts = (
                " [receipt seq: {}]".format(
                    ", ".join(str(s) for s in f["receipts"])
                )
                if f["receipts"]
                else ""
            )
            lines.append(
                "  {:<8} {}: {}{}".format(
                    f["severity"].upper(), f["code"], f["message"], receipts
                )
            )
    else:
        lines.append("no findings")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-inspect",
        description="Read-only back office: validate the receipt chain and "
        "surface what the day's orders show.",
    )
    parser.add_argument("ledger", help="ledger db path")
    parser.add_argument(
        "--pubkey", default=None, help="cashier public key PEM (enables signature checks)"
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    public_key = None
    if args.pubkey is not None:
        from cryptography.hazmat.primitives import serialization

        try:
            with open(args.pubkey, "rb") as fh:
                public_key = serialization.load_pem_public_key(fh.read())
        except (OSError, ValueError):
            print("usage: cannot read a public key from {}".format(args.pubkey))
            return 2

    try:
        rows = read_rows(args.ledger)
    except (sqlite3.OperationalError, ValueError) as exc:
        print("usage: cannot read receipts from {}: {}".format(args.ledger, exc))
        return 2

    report = build_report(rows, public_key)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0 if report["chain_valid"] else 1


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
