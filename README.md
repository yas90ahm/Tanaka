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
governance path, not the model.

## What it's for

This is a general **action broker** for AI agents: any consequential thing an
agent wants to do becomes a declared, scoped *capability* that gets bounded,
gated, and receipted. The slice ships three to show the range —
`cap.email.draft_reply.v1` (draft a reply), `cap.docs.summarize.v1` (summarize
a scoped document), `cap.payment.initiate.v1` (a high-risk, second-admin +
user-confirmation action). The point is the *shape*: drop in capabilities for
your problem — read a file from an allowed folder, query a record, call a tool
— and each one inherits capability-bounding, structural privacy, ephemeral
execution, the operator console, and a verifiable receipt for free. It fits
two deployments from one engine: enterprise agents over systems-of-record (the
Tanaka console), and computer-use agents on a personal machine (consumer mode,
below).

### Curating the menu — who does what

A menu item is two halves: a **behavior** (the code that performs the action)
and a **capability** (a configured menu item that uses a behavior). They have
different owners:

- **Behaviors are built by engineers, once.** A behavior is a pure
  `(_resource, source_text) -> output_text` transform in the dispatch table in
  `chef/chef_main.py`, plus an operator-facing entry in `menu/templates.py`.
  This is the only step that needs code. The slice ships three:
  `draft_reply`, `docs_summarize`, `payment_request`.
- **Capabilities are composed by a non-technical operator, no code, no JSON.**
  In the console's **Menu** screen they pick a behavior ("Summarize a
  document"), name it, set the care level (risk / ask-first / second-admin)
  and rate, and **Add to menu**. They can turn items on/off and remove them.
  Built-in items are shown locked. The capability is a real menu item that
  runs immediately, because it reuses a vetted behavior.

So a 59-year-old compliance officer curates the menu by clicking and filling in
a short form; an engineer is only needed when a genuinely new *kind* of action
must exist. (Under the hood the builder writes the descriptor for you; nothing
is hand-edited.)

### Two kinds of behavior — and one a non-technical person can author

"A behavior needs an engineer" is only half true:

- **Text behaviors** — read something and produce *formatted text* (a reply, an
  acknowledgement, a notice). The console ships a **Custom text response**
  building block: the operator writes a message template with fill-in fields
  (`$subject`, `$first_line`, `$word_count`, `$body`, …) and gets a working new
  behavior — **no code**. It's pure text rendering in the sandbox
  (`string.Template`, `$name` substitution only — no attribute access, no code,
  can't send or call out), so it's safe to let a non-technical person write,
  and it still gets all the bounding, permissions, and receipts.
- **Action behaviors** — ones with *new side effects or integrations* (actually
  move money, call an external API). These need an engineer, by design, because
  they touch the world in a new way that must be security-reviewed.

The dividing line is honest: anything that only *formats text* is no-code;
anything that *acts on the world in a new way* needs an engineer. The agents that will eventually sit in the
diner seat are **model-agnostic by construction**: anything that can emit the
order JSON below can use this infrastructure (see *The diner protocol*).

## What is real and what is mocked — read this first

| Component | Status |
|---|---|
| Hash-chained, signed, append-only ledger + standalone verifier | **Real** |
| Five-step cashier validation pipeline (nonce → menu → role → scope → rate) | **Real** |
| Signed-ticket verification inside the chef before any side effect | **Real** |
| Policy authoring round-trip (form output == engine input, byte-identical) | **Real** |
| Inspector (back office): chain-validated, operator-legible day report | **Real**, but pattern *surfacing*, not anomaly *detection* — no baseline, no behavioral model. |
| Adversarial drill: receipt-backed "resisted N/6" resistance report | **Real probes through the real pipeline**, but the probe set is fixed in code — the signed, continuously-updated curriculum of Essay 6 is a STUB. |
| Attestation | **MOCK.** `MockAttestor` signs a code hash. Every artifact says `"mock": true`. It proves the receipt *slot*, not TEE security. |
| Sandbox | **Subprocess contract, not a microVM guarantee.** Fresh subprocess + network-free import closure + workspace deletion demonstrate the *contract*; only Firecracker/gVisor provides the *guarantee*. |
| Kitchen | **Cooperative fixtures.** The mailbox is assumed honest; no provenance or integrity signing on stored content. |

`PROGRESS.md` carries the full component-by-component status with the same
flags, unsoftened.

## Fresh-clone bootstrap

Requires **Python 3.11+**. Runtime dependency: `cryptography`. Dev: `pytest`.

```sh
git clone <repo> && cd <repo>
python -m venv .venv
.venv/Scripts/activate            # Windows; on POSIX: source .venv/bin/activate

pip install -e ".[dev]"           # installs cryptography + pytest + sentinel-* CLIs

python -m pytest                  # 108 behavior tests
```

You can verify the committed demo chain **before generating anything** — the
public key ships with the repo, and verification needs only the public key:

```sh
python sentinel_slice/verify_ledger.py ledger.db sentinel_slice/keys/cashier_ed25519_public.pem
# OK verified=4
```

To **run your own instance** (place orders, use the console), generate your own
signing key. The private key is gitignored, so a fresh clone has only the demo
*public* key — `keygen` detects that and creates your keypair without fuss:

```sh
python -m sentinel_slice.keygen
# Note: a demo public key shipped with the repo but this clone has no private
# key. Creating your own keypair now...
```

**One thing to understand about keys:** receipts signed by one key only verify
against that key's public half. The committed `ledger.db` was signed by the
*demo* key, so once you generate your own key, run your own fresh ledger and
verify it against *your* public key. (`keygen` only refuses, demanding
`--force`, when a real *private* key is already present — it never silently
destroys a secret.)

### No-install path

You don't need `pip install` at all — with `cryptography` available you can run
everything via modules from the repo root: `python -m sentinel_slice.keygen`,
`python -m sentinel_slice.run_slice`, `python -m sentinel_slice.console.server`,
etc. The `pip install -e .` step just adds the `sentinel-*` console commands.

## Run the slice

One honest order and one prompt-injected probe into a single ledger, then the
standalone verifier over the resulting chain:

```sh
python -m sentinel_slice.run_slice demo-ledger.db
```

Expected output (a fresh db; the committed `ledger.db` already holds 4):

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
    "order_meta": {
      "principal": "user.kenji", "role": "account_manager",
      "capability_id": "cap.email.draft_reply.v1", "ts": "2026-06-10T12:00:00+00:00"
    },
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

Receipts name everyone involved (`order_meta`: who, what role, which
capability, when) — metadata only, never `args`, never content. The receipt
hash binds the row's **entire** key set, so v0.1 rows and v0.2 rows verify on
the same unbroken chain, and retro-attaching a key to an old row breaks it
visibly.

## The inspector (back office)

The cashier handles one order at a time; the inspector sees the whole day.
Read-only over the ledger (SELECT only), it validates the chain before
trusting a single row, then reports in operator language:

```sh
python -m sentinel_slice.inspector ledger.db --pubkey sentinel_slice/keys/cashier_ed25519_public.pem
```

```
INSPECTOR REPORT
chain: VALID (4 receipt(s), signatures checked)
orders: 2 fulfilled, 2 rejected
rejections: 2 OFF_MENU
principal user.kenji: 2 order(s), 1 fulfilled, 1 rejected, capabilities: cap.email.draft_reply.v1, forward_inbox
2 pre-v0.2 receipt(s) carry no order metadata (counted in totals, absent from per-principal lines)

FINDINGS
  HIGH     OFF_MENU_ATTEMPTS: 2 order(s) for capabilities not on the menu - the
           signature of a prompt-injected or misbehaving agent. The cashier
           refused before any execution. [receipt seq: 2, 4]
  INFO     ATTESTATION_IS_MOCK: 2 receipt(s) carry MOCK attestations - they
           prove the attestation slot, NOT a TEE. ...
```

(The committed `ledger.db` is itself the schema-evolution artifact: two v0.1
receipts and two v0.2 receipts on one unbroken chain — `OK verified=4`. The
v0.1 rows were never touched; the format grew by append, which is the only
way an append-only ledger is allowed to grow.)

Findings are deterministic rules with fixed severities — pattern surfacing,
not anomaly detection (no baseline, no time-windowing; that layer is still a
STUB). Exit 0 on a valid chain, 1 on a broken one. `--json` for machines.

## The adversarial drill (curriculum slot)

Essay 6's KnowBe4 move: simulated attacks fired through the **real** pipeline
— same menu, same policy file, same cashier, every probe receipted — so the
resistance report is backed by the same evidence an auditor would verify:

```sh
python -m sentinel_slice.curriculum.drill --ledger drill-ledger.db
```

```
ADVERSARIAL DRILL REPORT
resisted 6/6 simulated attacks; control order FULFILLED; chain valid
verdict: PASS

  ok   control_honest       expected FULFILLED          observed FULFILLED          receipt rcpt-…
  ok   prompt_injection     expected OFF_MENU           observed OFF_MENU           receipt rcpt-…
  ok   role_escalation      expected ROLE_NOT_PERMITTED observed ROLE_NOT_PERMITTED receipt rcpt-…
  ok   cross_tenant_scope   expected OUT_OF_SCOPE       observed OUT_OF_SCOPE       receipt rcpt-…
  ok   path_traversal       expected OUT_OF_SCOPE       observed OUT_OF_SCOPE       receipt rcpt-…
  ok   replay               expected REPLAY             observed REPLAY             receipt rcpt-…
  ok   rate_flood           expected RATE_LIMITED       observed RATE_LIMITED       receipt rcpt-…
```

The rate-flood probe reads the deployed limit from the same policy file the
cashier enforces, so weakening the policy makes the drill **fail** (exit 1) —
the drill detects drift, which is the reason the curriculum loop exists. The
probe set is fixed in code: it proves the curriculum *slot*; the signed,
layered, continuously updated curriculum is a STUB.

## Sentinel as an MCP gateway

MCP is how an agent (Claude) connects to tools, and its client already does
coarse "allow this tool?" prompts. What MCP does **not** do: check each call's
*arguments* (scope, rate, replay), or leave a *verifiable receipt*. Sentinel
rides on MCP's transport and adds exactly those.

```sh
python -m sentinel_slice.mcp_gateway --ledger my.db --principal user.kenji --role account_manager
```

It's a minimal MCP server (stdlib JSON-RPC 2.0 over stdio: `initialize` /
`tools/list` / `tools/call`). Each enabled capability becomes a tool; every
`tools/call` is turned into a Sentinel order, run through the cashier, executed
by the ephemeral chef, and recorded:

```jsonc
// tools/call draft_reply on the user's own thread -> governed + receipted
{"id":2,"result":{"content":[
  {"type":"text","text":"Re: Acme Corp Q3 onboarding\n\nThank you for your message..."},
  {"type":"text","text":"[Sentinel receipt rcpt-… | status FULFILLED | result digest b81a1d7c… | verifiable in the ledger]"}
],"isError":false}}

// tools/call draft_reply on SOMEONE ELSE'S thread -> refused, and still receipted
{"id":3,"result":{"content":[
  {"type":"text","text":"Refused by policy: OUT_OF_SCOPE. A signed rejection receipt was recorded (rcpt-…)."}
],"isError":true}}
```

That second case is the point: MCP's "always allow draft_reply" would let the
agent draft on *any* thread; here the same tool call is refused on its
arguments, and the refusal is tamper-evident evidence. It works for both
shapes — an enterprise fleet and a single user's Claude — because the agent
just speaks plain MCP. (Minimal subset: no resources/prompts/sampling yet.)

## The operator console (Tanaka)

The control surface that lets a non-engineer compliance officer author agent
policy correctly — the piece the essays call the actual product. Localhost
only, self-contained (loads zero external resources):

```sh
python -m sentinel_slice.console.server            # http://127.0.0.1:8787
```

Open that URL, paste a dev token (`dev-author-token` or `dev-reviewer-token`),
and you get three screens: **Capabilities** (the menu, with risk class and
which capabilities need a second admin), **Policies** (a structured editor —
pick capabilities, set rates, with live "industry-standard max" coaching;
**Simulate** shows exactly what an agent could/couldn't do under the candidate
policy *before* you commit; **Publish** records a signed version; sensitive
capabilities go **pending** until a second admin approves), and **Activity**
(the inspector's report live, each finding one click from its receipt, plus a
**Run Drill** button).

**Why a server here doesn't break the "air gap":** the console is the *control
plane*, not the data plane. Nothing in the enforcement path depends on it
(turn it off, agents still run and are governed). It is *structurally blind to
content* — like the cashier, it can reach only receipts (digests + metadata)
and policies, so a full compromise leaks no payload. Its one power, authoring,
is *signed, append-only, externally verifiable, and second-admin-gated*. It
binds **loopback only**, ships a strict CSP that forbids inline scripts and
every external origin, sends no CORS, and carries its token in a header (not a
cookie) so cross-origin pages can't forge calls. It is the operator's Settings
app, run inside their trust boundary — not a hosted service. And it *replaces*
hand-edited policy JSON, which was already an attack surface, just an invisible
one. Identity is a **MOCK** static token table (flagged loudly); the
separation-of-duties enforcement on top of it is real, and the seam swaps to
SSO without touching anything else.

Policy history is itself a signed, append-only chain — verify it standalone,
exactly like the receipt ledger:

```sh
python sentinel_slice/verify_policy_history.py policy_history.db sentinel_slice/keys/cashier_ed25519_public.pem
```

## Consumer mode (computer-use agents on your own machine)

The same engine, pointed at the most acute version of the problem: agents that
drive your whole computer (Operator, Claude computer use, Open Interpreter, …).
The agent reads and browses freely; the moment it reaches for something
irreversible or outward-facing, execution pauses and asks you — iOS-style:

```sh
python -m sentinel_slice.consumer       # self-contained demo (ephemeral key/ledger)
```

```
=== benign action: draft a reply (no friction expected) ===
  -> FULFILLED (asked you? False)

=== high-stakes action: initiate a payment ===
  ── action needs your approval ──
  wants to: Initiate payment  [cap.payment.initiate.v1]
  risk: high · side effects: money_movement
  allow [o]nce / [a]lways / [d]eny?  d
  -> DENIED_BY_USER (reason: USER_DENIED)

=== the receipt chain (what your agent actually did) ===
  seq 1 FULFILLED  -            cap.email.draft_reply.v1
  seq 2 REJECTED   USER_DENIED  cap.payment.initiate.v1
```

A prompt-injected agent meets your "deny" — and either way it's on the record.
"Allow always" remembers your choice so routine actions stop nagging.

### Setting permissions up front (no JSON, no prompts)

You don't have to wait to be asked. Open a plain Allow / Ask / Block screen and
decide what your agent may do, like app permissions on a phone:

```sh
python -m sentinel_slice.consumer.permissions
```

```
Your agent's permissions

  1. cap.docs.summarize.v1     risk:low   -> Allow  (default)
  2. cap.email.draft_reply.v1  risk:low   -> Allow  (default)
  3. cap.payment.initiate.v1   risk:high  -> Ask each time  (default)

Number to change (blank = save & quit): 3
  [a]llow / a[s]k / [b]lock for cap.payment.initiate.v1? b
```

- **Allow** — the agent does it without asking.
- **Ask** — it checks with you each time (the default for high-risk actions).
- **Block** — it can never do it; the attempt is auto-denied and recorded,
  with no prompt.

Defaults are sensible (low-risk Allow, high-risk Ask), so a first run just
works; you only touch what you care about. Choices save to a small file the
agent loop reads.

**Honest limit:** this gate only constrains the agent if the agent is *forced*
through the broker. On a real machine that requires the containment layer
below — the confirmation gate is the brain; the sandbox is the body.

## Sandbox backends (the containment seam)

The chef runs behind a swappable `Sandbox` interface (`chef/sandbox.py`):

- `SubprocessSandbox` (default) — a fresh subprocess with a network-free import
  closure and a destroyed workspace. This proves the **contract**, not an
  isolation **guarantee**: it does not contain a hostile chef.
- `ContainerSandbox` — runs the chef in a hardened OCI container
  (`--network none`, `--cap-drop ALL`, read-only rootfs, non-root,
  `--pids-limit`, no-new-privileges), optionally under **gVisor**
  (`--runtime=runsc`) for a real user-space-kernel isolation boundary.

  This is genuine isolation, and it is **actually exercised** — not just
  asserted. The `sandbox-isolation` GitHub Actions job (`.github/workflows/
  sandbox.yml`) builds the chef image (`Dockerfile`), runs a real chef inside
  the hardened container, then **re-runs it under gVisor (runsc)**, asserting
  it produces the same signed FULFILLED receipt as the subprocess backend —
  just contained. Locally / on Windows the heavy run is env-gated and skips;
  set `SENTINEL_TEST_CONTAINER=1` (with a built `sentinel-chef` image, and
  `SENTINEL_SANDBOX_RUNTIME=runsc` for gVisor) to run it yourself. The command
  construction is unit-tested exactly regardless. Firecracker microVMs slot in
  behind the same `run()` — this is the seam that turns "sandbox is a
  contract" into "sandbox is a guarantee" without changing a type signature.

## Layer map (essays → code)

| Takeout layer | Module | Job |
|---|---|---|
| Diner | `diner/agent.py`, `gateway.py` | Scripted reference agent (honest + injected modes); model-agnostic JSON counter |
| Menu | `menu/catalog.py` + `capabilities/*.json` | Declared, finite capability catalog |
| Cashier | `cashier/engine.py`, `policy.py`, `store.py` | Five-step validation, ticket minting, rejection receipts; structurally kitchen-blind |
| Kitchen | `kitchen/fixtures/` | System of record (cooperative fixtures, incl. the poisoned email) |
| Chef + Window | `chef/chef_main.py`, `chef/runner.py`, `window/serving.py` | Ephemeral execution of the signed ticket; per-order serving window |
| Receipt | `ledger/receipts.py`, `verify_ledger.py` | Append-only signed hash chain; standalone verification |
| Inspector (back office) | `inspector.py` | Chain-validated, operator-legible report over the whole day |
| Curriculum (drill slot) | `curriculum/drill.py` | Fixed adversarial probe suite; receipt-backed resistance report |
| Operator console (Tanaka) | `console/` | Localhost UI + API to author policy, simulate, publish (second-admin gated), and watch activity |
| Authoring (Tanaka, in miniature) | `authoring/policy_form.py` + `policies/*.json` | One-screen form whose output the engine consumes byte-for-byte |
| Loop | `loop.py` | The credential boundary — the only place the private key lives |

## Acceptance tests

All 10 SPEC acceptance tests pass (`tests/test_at01_*` … `test_at10_*`),
plus unit, hardening-regression, gateway, inspector, drill, and console tests
— 108 total. Highlights:

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

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Permissive, with a
patent grant; you may use, modify, and redistribute, including commercially,
provided you keep the notices. Contributions are accepted under the same
license with a DCO sign-off (see [CONTRIBUTING.md](CONTRIBUTING.md)).
