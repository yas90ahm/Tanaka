# CLAUDE.md — Build Instructions: Sentinel Loop Vertical Slice

You are building the vertical slice defined in SPEC.md and ARCHITECTURE.md
(both at repo root). Read both fully before writing any code. Where this
file and those files conflict, SPEC.md wins.

## Non-negotiables

1. **Every test asserts a behavior or value** — exact dict equality, full
   receipt contents, process-spawn counts, exit codes. No shape-only or
   substring-only assertions. A test that would still pass if the component
   were a stub is not a test.
2. **Nothing mocked is allowed to look real.** MockAttestor output must
   contain `"mock": true`. PROGRESS.md must flag every mock loudly. If any
   component quietly needs a capability the spec says it can't have
   (network in the chef, kitchen imports in the cashier), STOP and flag it
   rather than working around it.
3. **The ledger is append-only by construction.** No UPDATE/DELETE anywhere
   in ledger code. Grep yourself before claiming done.
4. **Canonical JSON for all hashing/signing:** `sort_keys=True,
   separators=(",", ":")`, UTF-8 bytes. One helper function, used
   everywhere, tested directly.
5. **No LLM anywhere in the slice.** The diner is a deterministic script.
6. Python 3.11+, deps limited to `cryptography` and `pytest`.

## Build order — stop at each STOP and report before continuing

**Phase 1 — Spine.** Types (Capability, Order, Ticket, Receipt), canonical
JSON helper, keygen utility (one cashier/ledger keypair, PEM on disk).
Tests: canonical JSON is stable across dict ordering; receipt hash changes
when any field changes. STOP.

**Phase 2 — Ledger + verifier.** Append-only receipt store with genesis
hash sha256(b"GENESIS"); standalone verify_ledger.py (zero package
imports). Tests: 100-receipt chain verifies; flipping one byte in row 50
makes verifier exit 1 and print seq 50. STOP.

**Phase 3 — Menu + Cashier.** Capability JSON loader; policy loader; the
validation pipeline in SPEC order (nonce → on-menu → role → scope → rate).
Rejections append receipts with the exact reason codes from SPEC. Tests:
acceptance tests 2, 3, 4, 5 pass; import-closure test proves cashier cannot
reach kitchen/ modules. STOP.

**Phase 4 — Chef + Window + MockAttestor.** Subprocess runner; chef_main
verifies ticket signature on stdin before acting, refuses on bad sig; reads
only the fixture path in scoped_args; writes draft to window/<order_id>/;
tempdir destroyed on exit. Tests: acceptance tests 1, 7, 8 pass; a chef
given a ticket with a forged signature exits nonzero and touches nothing.
STOP.

**Phase 5 — Authoring round-trip + probe.** Policy form (CLI prompts are
fine) emitting policies/account_manager.json consumed verbatim by the
engine; the poisoned fixture email; the injected-diner probe attempting
forward_inbox. Tests: acceptance tests 6, 9, 10 pass; full honest run and
full injected run each produce a verifiable chain. STOP.

## When done

- All 10 acceptance tests from SPEC.md pass; name each test after its
  acceptance number (test_at01_..., test_at02_...).
- Run one honest order and one injected order; commit the resulting
  ledger.db and show `verify_ledger.py` output for it.
- Write PROGRESS.md at repo root: every component BUILT / PARTIAL / STUB,
  one blunt sentence each. List explicitly: attestation is MOCK, sandbox is
  subprocess-contract not microVM-guarantee, kitchen is cooperative
  fixtures. Do not soften these.
