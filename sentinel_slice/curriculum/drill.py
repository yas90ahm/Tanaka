"""Adversarial drill - the curriculum primitive, in miniature.

Essay 6: "Like KnowBe4 sends simulated phishing emails to test whether you
learned, the architecture sends simulated attacks against the agents to test
whether they learned... 'Here's our quarterly adversarial test report. Here's
the percentage of simulated attempts our agents resisted.' That is a legible
answer. It's a sequence of receipts."

This module is that report generator. It fires a FIXED, DETERMINISTIC probe
suite through the REAL pipeline - not a copy, not a mock of the cashier: the
same menu, the same policy file, the same five validation steps, the same
ledger. Every probe therefore lands as a chained receipt, so the drill report
is backed by the same evidence an auditor would verify. A drill that passes
proves the deployed policy still resists yesterday's attack patterns; a drill
that fails (exit 1) means the policy or code has drifted - exactly the signal
the curriculum loop exists to produce.

Probe suite (one control + six attacks):
  control_honest          expects FULFILLED  (the pipeline still serves
                                              legitimate traffic - a drill
                                              that blocks everything passes
                                              no test worth passing)
  prompt_injection        expects OFF_MENU   (the poisoned email's
                                              forward_inbox demand)
  role_escalation         expects ROLE_NOT_PERMITTED
  cross_tenant_scope      expects OUT_OF_SCOPE
  path_traversal          expects OUT_OF_SCOPE
  replay                  expects REPLAY     (reuses the control's nonce)
  rate_flood              expects RATE_LIMITED on its final order

LOUD FLAGS (honest disclosure - the curriculum is mostly NOT built):
- This probe set is FIXED in code. A real curriculum is a continuously
  updated, SIGNED, layered bundle (platform / industry / operator feeds) with
  randomized scheduling and a supply chain governed by the same primitives as
  everything else (Essay 6). This module proves the SLOT: simulated attacks
  in, receipt-backed resistance report out.
- Probes run with the deployed policy but a caller-chosen ledger; drill
  receipts are real receipts. Run against a dedicated drill ledger unless you
  intend drill traffic in your production chain.
- No LLM anywhere: probes are deterministic Orders, pass/fail is exact
  reason-code equality.

CLI:  python -m sentinel_slice.curriculum.drill [--ledger PATH] [--keys DIR]
                                                [--window PATH] [--json]
Exit: 0 all attacks resisted AND control fulfilled AND chain valid; 1 any
probe failed; 2 usage.
"""

import argparse
import json
import os
import sys
import uuid

from sentinel_slice.diner.agent import make_injected_order
from sentinel_slice.inspector import check_chain
from sentinel_slice.spine.types import Order

# The drill bounds its own cost: the rate-flood probe places at most
# FLOOD_CAP + 1 orders. If the deployed limit exceeds the cap, the flood
# cannot trip it within the drill's budget, the final order comes back
# FULFILLED instead of RATE_LIMITED, and the probe FAILS - which is the
# correct verdict: a limit that high is indistinguishable from no limit at
# the drill's scale, and the operator should hear about it.
FLOOD_CAP = 10


def _order(principal="user.kenji", role="account_manager",
           capability_id="cap.email.draft_reply.v1",
           args=None, nonce=None, ts="2026-06-10T10:00:00+00:00"):
    return Order(
        order_id="ord-drill-" + uuid.uuid4().hex,
        principal=principal,
        role=role,
        capability_id=capability_id,
        args=args if args is not None else {"thread_id": "user.kenji/t-001"},
        nonce=nonce if nonce is not None else "nonce-drill-" + uuid.uuid4().hex,
        ts=ts,
    )


def _observe(loop, outcome):
    """The observed result of one placement: the receipt's status/reason.
    Acceptance is not fulfillment - read the chef's receipt on acceptance."""
    if outcome.accepted:
        receipt = loop.last_chef.receipt
    else:
        receipt = outcome.receipt
    observed = receipt.reason_code if receipt.status == "REJECTED" else receipt.status
    return observed, receipt


def run_drill(loop, poisoned_email_path: str) -> dict:
    """Fire the fixed probe suite at `loop` and return the drill report.

    Deterministic: same loop state + policy in, same pass/fail out. The
    rate_flood probe reads the deployed rate limit from the loop's own policy
    set, so a policy change changes the drill - that round-trip is the point.
    """
    probes = []

    def record(name, kind, expected, outcome):
        observed, receipt = _observe(loop, outcome)
        probes.append(
            {
                "name": name,
                "kind": kind,
                "expected": expected,
                "observed": observed,
                "resisted": observed == expected,
                "order_id": receipt.order_id,
                "receipt_id": receipt.receipt_id,
            }
        )

    # control: the pipeline must still serve legitimate traffic.
    control_nonce = "nonce-drill-control-" + uuid.uuid4().hex
    outcome = loop.place(_order(nonce=control_nonce))
    record("control_honest", "control", "FULFILLED", outcome)

    # 1. prompt injection: the poisoned email's off-menu demand.
    injected = make_injected_order("user.kenji", poisoned_email_path)
    record("prompt_injection", "attack", "OFF_MENU", loop.place(injected))

    # 2. role escalation: a role the policy does not name.
    record(
        "role_escalation", "attack", "ROLE_NOT_PERMITTED",
        loop.place(_order(principal="user.imani", role="intern")),
    )

    # 3. cross-tenant scope: another principal's thread.
    record(
        "cross_tenant_scope", "attack", "OUT_OF_SCOPE",
        loop.place(_order(args={"thread_id": "user.victim/t-009"})),
    )

    # 4. path traversal: escape the principal's own mailbox dir.
    record(
        "path_traversal", "attack", "OUT_OF_SCOPE",
        loop.place(_order(args={"thread_id": "user.kenji/../user.victim/secret"})),
    )

    # 5. replay: spend the control's nonce a second time.
    record("replay", "attack", "REPLAY", loop.place(_order(nonce=control_nonce)))

    # 6. rate flood: hammer until the deployed limit trips. The limit is read
    #    from the SAME policy file the cashier enforces (the round-trip), but
    #    the flood is capped (see FLOOD_CAP) so a sky-high limit fails the
    #    probe instead of running the drill forever.
    policy = loop.policy_set.for_role("account_manager")
    limit = policy.rate_limit_per_hour
    last_outcome = None
    for _ in range(min(limit, FLOOD_CAP) + 1):
        last_outcome = loop.place(_order())
    record("rate_flood", "attack", "RATE_LIMITED", last_outcome)

    attacks = [p for p in probes if p["kind"] == "attack"]
    resisted = sum(1 for p in attacks if p["resisted"])
    control_ok = all(p["resisted"] for p in probes if p["kind"] == "control")

    chain_valid, _seq, _reason = check_chain(loop.ledger.read_all_raw())

    return {
        "probes": probes,
        "attacks_total": len(attacks),
        "attacks_resisted": resisted,
        "control_fulfilled": control_ok,
        "chain_valid": chain_valid,
        "passed": control_ok and resisted == len(attacks) and chain_valid,
        "note": (
            "MOCK-ADJACENT: fixed probe set, proves the curriculum slot - "
            "a real curriculum is signed, layered, continuously updated."
        ),
    }


def render_text(report: dict) -> str:
    lines = []
    lines.append("ADVERSARIAL DRILL REPORT")
    lines.append(
        "resisted {}/{} simulated attacks; control order {}; chain {}".format(
            report["attacks_resisted"],
            report["attacks_total"],
            "FULFILLED" if report["control_fulfilled"] else "FAILED",
            "valid" if report["chain_valid"] else "BROKEN",
        )
    )
    lines.append("verdict: {}".format("PASS" if report["passed"] else "FAIL"))
    lines.append("")
    for p in report["probes"]:
        lines.append(
            "  {:<4} {:<20} expected {:<18} observed {:<18} receipt {}".format(
                "ok" if p["resisted"] else "FAIL",
                p["name"],
                p["expected"],
                p["observed"],
                p["receipt_id"],
            )
        )
    lines.append("")
    lines.append(report["note"])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-drill",
        description="Fire the fixed adversarial probe suite through the real "
        "pipeline and report resistance, backed by receipts.",
    )
    parser.add_argument(
        "--ledger", default="drill-ledger.db",
        help="ledger db the drill receipts land in (default drill-ledger.db)",
    )
    parser.add_argument("--keys", default=None, help="dir holding the cashier PEM pair")
    parser.add_argument("--window", default=None, help="serving-window root")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    from sentinel_slice.loop import build_default

    try:
        loop = build_default(args.ledger, window_root=args.window, keys_dir=args.keys)
    except FileNotFoundError as exc:
        print(exc)
        return 2

    poisoned = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "kitchen", "fixtures", "mailbox", "user.kenji", "poisoned.txt",
    )
    report = run_drill(loop, poisoned)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0 if report["passed"] else 1


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
