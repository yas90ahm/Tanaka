# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Cashier runtime state: single-use nonces and a trailing-window rate
counter keyed by (principal, capability_id).

STRUCTURAL BLINDNESS (CLAUDE.md / Phase-3 contract §1): this module performs
NO I/O, reads no fixture mailbox, and imports nothing under
sentinel_slice.kitchen. It holds only in-memory state. The clock is
injectable so tests drive the rate window deterministically.
"""

import time

# Trailing rate window: one hour, half-open. A record at time `ts` counts
# toward the window ending at now() iff (now() - ts) < RATE_WINDOW_SECONDS.
# A record exactly RATE_WINDOW_SECONDS old does NOT count.
RATE_WINDOW_SECONDS = 3600.0


class CashierStore:
    """Mutable, in-memory cashier state.

    - `_seen_nonces`: a set of every nonce ever presented (single-use).
    - `_history`: dict keyed by (principal, capability_id) -> list[float] of
      accepted-record timestamps, for the trailing rate window.
    """

    def __init__(self, *, now=time.time) -> None:
        """now: zero-arg callable returning a float epoch-seconds clock.
        Default time.time. Tests inject a deterministic clock. The callable
        is read freshly on each rate operation so a test advancing the clock
        sees the window slide."""
        self._now = now
        self._seen_nonces: set[str] = set()
        self._history: dict[tuple[str, str], list[float]] = {}

    # ---- nonce: single-use ----
    def nonce_is_spent(self, nonce: str) -> bool:
        """READ-ONLY: report whether `nonce` has already been registered,
        WITHOUT registering it. Used by the pure `evaluate_order` (and the
        console's Simulate) so a verdict can be computed with zero state
        change. The mutating check-and-register is `nonce_seen` below."""
        return nonce in self._seen_nonces

    def nonce_seen(self, nonce: str) -> bool:
        """Check-and-register in one atomic call.

        FIRST sight of `nonce` registers it and returns False (unseen);
        every REPEAT returns True (seen). The engine calls this exactly once
        per order at pipeline step 1, so every order — accepted or rejected —
        consumes its nonce on first presentation."""
        if nonce in self._seen_nonces:
            return True
        self._seen_nonces.add(nonce)
        return False

    # ---- rate: trailing RATE_WINDOW_SECONDS window keyed by (principal, capability_id) ----
    def rate_count(self, principal: str, capability_id: str) -> int:
        """Return how many accepted records exist for (principal,
        capability_id) whose timestamp is within the trailing window ending
        at now() — i.e. count of recorded ts where now() - ts < 3600.0.
        Does NOT record anything."""
        now = self._now()
        history = self._history.get((principal, capability_id))
        if not history:
            return 0
        return sum(1 for ts in history if now - ts < RATE_WINDOW_SECONDS)

    def record_accept(self, principal: str, capability_id: str) -> None:
        """Append now() to the history for (principal, capability_id).
        Called by the engine ONLY when an order is accepted (a ticket is
        minted), AFTER the rate check passes."""
        self._history.setdefault((principal, capability_id), []).append(self._now())
