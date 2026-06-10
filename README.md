# Sentinel Loop — Vertical Slice

A working, verifiable vertical slice of the **takeout model** for AI-agent
governance: an agent (the *diner*) that holds **no credentials** orders a
declared capability from a *menu*; a *cashier* validates the order against
operator-authored policy without ever seeing content; an ephemeral *chef*
subprocess executes exactly the signed ticket and nothing else; the result is
served through a *window*; and every order — fulfilled **or rejected** —
produces a hash-chained, Ed25519-signed *receipt* that a standalone script can
verify holding only the ledger file and a public key.

The slice exists to demonstrate four claims (see `SPEC.md`):

1. **Capability-bounded** — all agent power is mediated through ordering from
   a declared menu. Off-menu orders are rejected before any execution.
2. **Structurally private** — the cashier and ledger never see payload
   content; receipts carry a SHA-256 digest of the result, never the result.
3. **Ephemeral** — each order gets a fresh chef subprocess whose workspace is
   destroyed on completion.
4. **Audit-legible** — the rejection of a prompt-injected order is itself a
   chained receipt (`reason_code: OFF_MENU`). That receipt is the money
   artifact.

There is **no LLM anywhere in this slice** — the thesis under test is the
governance path, not the model. The agents that will eventually sit in the
diner seat are **model-agnostic by construction**: anything that can emit the
order JSON below can use this infrastructure (see *The diner protocol*).

## What is real and what is mocked — read this first

| Component | Status |
|---|---|
| Hash-chained, signed, append-only ledger + standalone verifier | **Real** |
| Five-step cashier validation pipeline (nonce → menu → role → scope → rate) | **Real** |
| Signed-ticket verification inside the chef before any side effect | **Real** |
| Policy authoring round-trip (form output == engine input, byte-identical) | **Real** |
| Attestation | **MOCK.** `MockAttestor` signs a code hash. Every artifact says `"mock": true`. It proves the receipt *slot*, not TEE security. |
| Sandbox | **Subprocess contract, not a microVM guarantee.** Fresh subprocess + network-free import closure + workspace deletion demonstrate the *contract*; only Firecracker/gVisor provides the *guarantee*. |
| Kitchen | **Cooperative fixtures.** The mailbox is assumed honest; no provenance or integrity signing on stored content. |

`PROGRESS.md` carries the full component-by-component status with the same
flags, unsoftened.

## Fresh-clone bootstrap

Requires Python 3.11+. The only runtime dependency is `cryptography`.

```sh
python -m venv .venv
.venv/Scripts/activate            # Windows; on POSIX: source .venv/bin/activate
pip install -e ".[dev]"

# The signing key is gitignored — a fresh clone must generate its own pair.
python -m sentinel_slice.keygen

python -m pytest                  # 62 tests, all behavior assertions
```

**Key caveat:** the committed `ledger.db` was signed with the original
(uncommitted) private key and verifies against the committed
`sentinel_slice/keys/cashier_ed25519_public.pem`. If you regenerate the
keypair, verify *your own* runs against *your* public key and start a fresh
ledger file — receipts signed by one key never verify against another.
`keygen` refuses to overwrite an existing pair unless you pass `--force`.

## Run the slice

One honest order and one prompt-injected probe into a single ledger, then the
standalone verifier over the resulting chain:

```sh
python -m sentinel_slice.run_slice demo-ledger.db
```

Expected output:

```
honest: accepted=True fulfilled=True status=FULFILLED digest=<sha256 hex>
injected: accepted=False reason=OFF_MENU
OK verified=2
```

Verify any ledger independently — the verifier imports **nothing** from the
package; it needs only the db file and the public key:

```sh
python sentinel_slice/verify_ledger.py demo-ledger.db sentinel_slice/keys/cashier_ed25519_public.pem
```

Tamper with any row and it exits 1 naming the first broken link
(`FAIL seq=N reason=hash_mismatch`).

## The diner protocol (model-agnostic agent interface)

Agents never import this package, never hold keys, and never see the kitchen.
An agent is anything — any model, any vendor, any language — that emits one
JSON object per order:

```json
{
  "order_id":      "ord-001",
  "principal":     "user.kenji",
  "role":          "account_manager",
  "capability_id": "cap.email.draft_reply.v1",
  "args":          {"thread_id": "user.kenji/t-001"},
  "nonce":         "nonce-001",
  "ts":            "2026-06-10T12:00:00+00:00"
}
```

Pipe it through the gateway (one order on stdin, one outcome on stdout):

```sh
python -m sentinel_slice.gateway --ledger demo-ledger.db < order.json
```

The outcome JSON carries both of the architecture's paths at once, still
separated: the **content path** (`draft_b64`, `window_dir` — the meal, handed
only to the diner) and the **evidence path** (`receipt` — digest, hashes,
signature; never content):

```json
{
  "order_id": "ord-001",
  "accepted": true,
  "status": "FULFILLED",
  "reason_code": null,
  "ticket_id": "tkt-…",
  "receipt": {
    "receipt_id": "rcpt-…",
    "status": "FULFILLED",
    "result_digest": "<sha256 of the draft bytes>",
    "attestation": {"mock": true, "...": "…"},
    "prev_hash": "…", "this_hash": "…", "sig": "<base64>"
  },
  "window_dir": ".../window/orders/ord-001",
  "draft_b64": "<the draft, base64>"
}
```

A rejected order returns `"accepted": false` with the exact `reason_code`
(`OFF_MENU`, `ROLE_NOT_PERMITTED`, `OUT_OF_SCOPE`, `REPLAY`, `RATE_LIMITED`)
and the chained rejection receipt. A malformed order (bad JSON, missing or
unknown keys) is refused with `MALFORMED_ORDER`, exit 2, and **no** ledger row
— it never acquired an identity the chain could record (a production gateway
would receipt these under a gateway-assigned identity).

In-process, the same surface is `sentinel_slice.gateway.place_order_json(loop,
text)`; the scripted reference diner lives in `sentinel_slice/diner/agent.py`.
Swapping the scripted diner for an LLM-driven one changes **nothing** on the
governance side — that is the point.

## Layer map (essays → code)

| Takeout layer | Module | Job |
|---|---|---|
| Diner | `diner/agent.py`, `gateway.py` | Scripted reference agent (honest + injected modes); model-agnostic JSON counter |
| Menu | `menu/catalog.py` + `capabilities/*.json` | Declared, finite capability catalog |
| Cashier | `cashier/engine.py`, `policy.py`, `store.py` | Five-step validation, ticket minting, rejection receipts; structurally kitchen-blind |
| Kitchen | `kitchen/fixtures/` | System of record (cooperative fixtures, incl. the poisoned email) |
| Chef + Window | `chef/chef_main.py`, `chef/runner.py`, `window/serving.py` | Ephemeral execution of the signed ticket; per-order serving window |
| Receipt | `ledger/receipts.py`, `verify_ledger.py` | Append-only signed hash chain; standalone verification |
| Authoring (Tanaka, in miniature) | `authoring/policy_form.py` + `policies/*.json` | One-screen form whose output the engine consumes byte-for-byte |
| Loop | `loop.py` | The credential boundary — the only place the private key lives |

## Acceptance tests

All 10 SPEC acceptance tests pass (`tests/test_at01_*` … `test_at10_*`),
plus unit, hardening-regression, and gateway tests — 62 total. Highlights:

- **AT01** honest order → exact deterministic draft in the window; receipt
  carries the digest and **no substring** of the draft appears anywhere in the
  raw ledger bytes.
- **AT02** the injected `forward_inbox` order spawns **zero** chef processes
  and leaves a chained `OFF_MENU` rejection receipt.
- **AT06** flipping one byte in row 50 of a 100-receipt chain makes the
  verifier exit 1 and name seq 50.
- **AT07** the chef's import closure contains no network modules.
- **AT09** changing the rate limit in the form-emitted JSON changes
  enforcement; form output and engine input are byte-identical.

## Production swap map (designed seams — do not read as built)

Each mock sits behind a contract whose replacement changes no type signature:
chef subprocess → Firecracker/gVisor microVM; `MockAttestor` → TEE quote
verification; fixture mailbox → provenance-signed store; in-process gateway →
authenticated FastAPI surface; CLI policy form → the Tanaka operator console;
single capability → operator-curated catalog. The thesis behind the design
lives in the agent-infrastructure essay series (trust paradox → agent OS →
takeout model → operator-as-buyer → threat surface → continuous curriculum →
institutional layer).
