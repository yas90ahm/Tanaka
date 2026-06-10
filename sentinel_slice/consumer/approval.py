"""Consumer-mode approval — human-in-the-loop friction for high-stakes actions.

This is the consumer face of the same engine the enterprise console drives. On
your own machine there is no compliance officer: YOU are the operator, and
policy authoring collapses into iOS-style permission prompts. When a
computer-use agent tries to do something irreversible or outward-facing (a
capability flagged `requires_user_confirmation`), execution pauses and asks —
allow once, allow always, or deny — exactly like granting an app the camera.

The cashier still authorizes by policy first; this is a SECOND gate at
EXECUTION time. A denial is recorded as a chained receipt (the money artifact
again: "your agent tried X, you said no, here's the proof"). An "allow always"
records a standing grant so the same (principal, capability) won't ask again.

No LLM, no network. The decision is a human's, or — in tests — a scripted one.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ApprovalDecision:
    """One human verdict on one pending action.

    allow=False  -> the action is denied; it does not execute.
    remember=True with allow=True -> grant standing approval for this
        (principal, capability) so future identical actions skip the prompt.
    remember is ignored when allow is False (we never auto-deny silently —
        every attempt should still surface)."""
    allow: bool
    remember: bool = False


class ApprovalStore:
    """In-memory standing grants: (principal, capability_id) pairs the user
    chose to 'always allow'. The slice keeps these in memory for the life of
    the session; a real client would persist them per user, revocably."""

    def __init__(self) -> None:
        self._grants: set[tuple[str, str]] = set()

    def has_grant(self, principal: str, capability_id: str) -> bool:
        return (principal, capability_id) in self._grants

    def grant(self, principal: str, capability_id: str) -> None:
        self._grants.add((principal, capability_id))

    def revoke(self, principal: str, capability_id: str) -> None:
        self._grants.discard((principal, capability_id))


class ScriptedApprover:
    """A deterministic approver for tests and scripted demos. Supply either a
    single ApprovalDecision (used for every prompt) or a list consumed in
    order (raises if it runs out — a test that prompts more than expected
    should fail loudly)."""

    def __init__(self, decisions) -> None:
        if isinstance(decisions, ApprovalDecision):
            self._fixed = decisions
            self._queue = None
        else:
            self._fixed = None
            self._queue = list(decisions)
        self.prompts: list[tuple[str, str]] = []  # (principal, capability_id) asked

    def decide(self, *, order, capability) -> ApprovalDecision:
        self.prompts.append((order.principal, capability.id))
        if self._fixed is not None:
            return self._fixed
        if not self._queue:
            raise AssertionError("ScriptedApprover ran out of decisions")
        return self._queue.pop(0)


class CliApprover:
    """Interactive approver: prints the pending action and reads one line.
       o / once   -> allow once
       a / always -> allow and remember (standing grant)
       d / deny   -> deny (default on empty / anything else)
    Input/output are injectable so the consumer CLI and tests can drive it."""

    def __init__(self, input_fn=input, print_fn=print) -> None:
        self._input = input_fn
        self._print = print_fn

    def decide(self, *, order, capability) -> ApprovalDecision:
        self._print("")
        self._print("  ── action needs your approval ─────────────────────────")
        self._print("  agent (principal): {}".format(order.principal))
        self._print("  wants to:          {}  [{}]".format(
            capability.name, capability.id))
        self._print("  risk:              {} · side effects: {}".format(
            capability.risk_class, capability.side_effects))
        self._print("  on:                {}".format(order.args))
        ans = (self._input("  allow [o]nce / [a]lways / [d]eny? ") or "").strip().lower()
        if ans in ("o", "once"):
            return ApprovalDecision(allow=True, remember=False)
        if ans in ("a", "always"):
            return ApprovalDecision(allow=True, remember=True)
        return ApprovalDecision(allow=False, remember=False)
