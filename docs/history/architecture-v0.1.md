# Sentinel Loop — Slice Architecture (v0.1)

> Historical architecture from the first slice. It does not describe every current backend or console feature.

Layers as contracts, not metaphor. Python 3.11+, stdlib-first. Dependencies:
`cryptography` (Ed25519), `pytest`. SQLite for the ledger. No web framework
needed for the slice — the API is in-process; FastAPI comes later.

## Repo layout

```
sentinel_slice/
  diner/agent.py          # scripted diner: honest + injected modes
  menu/catalog.py         # capability registry, loads capabilities/*.json
  cashier/engine.py       # order validation, policy eval, ticket minting
  cashier/policy.py       # policy loader; consumes policies/*.json verbatim
  kitchen/fixtures/       # fixture mailbox incl. poisoned_email.txt
  chef/runner.py          # spawns chef subprocess per ticket
  chef/chef_main.py       # the subprocess entrypoint (isolated module)
  attestor/mock.py        # MockAttestor — signs code hash, labeled MOCK
  ledger/receipts.py      # hash-chained, Ed25519-signed receipt store
  window/serving.py       # serving window: per-order output dir for diner
  authoring/policy_form.py# one-screen form (CLI or single HTML) → JSON
  verify_ledger.py        # STANDALONE verifier, no package imports
  tests/                  # behavior tests per SPEC acceptance list
  PROGRESS.md
```

## Core types (the spine — build these first)

```python
@dataclass(frozen=True)
class Capability:
    id: str                 # "cap.email.draft_reply.v1"
    name: str
    inputs: dict[str, str]  # {"thread_id": "string"}
    outputs: dict[str, str] # {"draft": "text"}
    side_effects: str       # "none"
    scope: str              # "acting user's review queue"
    risk_class: str         # "low"

@dataclass(frozen=True)
class Order:
    order_id: str           # uuid4
    principal: str          # "user.kenji"
    role: str               # "account_manager"
    capability_id: str
    args: dict
    nonce: str              # replay defense
    ts: str                 # ISO 8601 UTC

@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    order_id: str
    capability_id: str
    scoped_args: dict       # args AFTER cashier scope-narrowing
    issued_ts: str
    cashier_sig: bytes      # Ed25519 over canonical JSON of above

@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    order_id: str
    ticket_id: str | None   # None when rejected (no ticket minted)
    status: str             # "FULFILLED" | "REJECTED"
    reason_code: str | None # OFF_MENU | ROLE_NOT_PERMITTED | OUT_OF_SCOPE
                            # | REPLAY | None
    result_digest: str | None  # sha256 hex of output bytes; NEVER content
    attestation: dict | None   # MockAttestor output, {"mock": true, ...}
    prev_hash: str          # hex; genesis = sha256(b"GENESIS")
    this_hash: str          # sha256(canonical_json(all fields above))
    sig: bytes              # Ed25519 over this_hash
```

Canonical JSON everywhere: `json.dumps(obj, sort_keys=True,
separators=(",", ":"))`. Hash and sign the canonical bytes only.

## Flow (one order, six layers)

```
diner.place(Order)
  → cashier.validate(Order)
      checks, in order: nonce unseen → capability on menu → role permitted
      by policy → args within capability scope → rate limit
      FAIL → ledger.append(Receipt REJECTED, reason)   [no ticket, no chef]
      PASS → Ticket minted + signed
  → chef.runner.spawn(Ticket)
      fresh subprocess, cwd = tempdir; reads ONLY the fixture path named in
      scoped_args; writes draft to window/<order_id>/; exits; tempdir gone
  → attestor.mock.quote(chef_code_hash)                 [labeled MOCK]
  → ledger.append(Receipt FULFILLED, digest=sha256(draft), attestation)
  → diner reads draft from window/<order_id>/           [content path]
     diner reads receipt from ledger                    [evidence path]
```

**Privacy invariant:** content flows diner ← window ← chef. Evidence flows
ledger ← cashier/chef. The two paths never carry each other's data. Test 1
enforces this by asserting no draft substring appears in the receipt or
ledger file.

## Component contracts

- **Menu** — `catalog.get(capability_id) -> Capability | None`. Capabilities
  are JSON files; the registry is read-only at runtime.
- **Cashier** — pure function from `(Order, PolicySet, NonceStore) ->
  Ticket | Rejection(reason_code)`. No I/O except nonce store. The cashier
  module must have no import path to the kitchen fixtures (structural
  blindness, assert via import-closure test).
- **Chef** — `chef_main.py` is runnable only via the runner. It receives the
  signed ticket on stdin, verifies the cashier signature before doing
  anything, refuses on mismatch. Import closure must exclude all network
  modules (test 7).
- **Ledger** — append-only SQLite table `receipts(seq INTEGER PRIMARY KEY,
  json TEXT)`. `append()` computes prev_hash from the last row. No update or
  delete statements anywhere in the module.
- **Verifier** — `verify_ledger.py <ledger.db> <pubkey.pem>`: walks the
  chain, recomputes every hash, checks every signature, exits 0/1, prints
  the seq of the first broken link. Must not import from `sentinel_slice`.
- **Authoring form** — one screen: role picker, capability picker, rate
  slider. Emits `policies/account_manager.json`. The engine loads that file
  byte-for-byte. No translation layer — the round trip IS the thesis.

## What this maps to later (do not build now)

Chef subprocess → Firecracker microVM. MockAttestor → TEE quote
verification. Fixture mailbox → provenance-signed store. In-process calls →
FastAPI surface. Policy form → Tanaka console. Each is a swap behind an
existing contract; the slice's interfaces are designed so none of these
swaps changes a type signature.
