# Tanaka Console — Build Scope (v0.3)

The operator-legible control surface. This is the piece the essays call the
actual product: the layer that lets a non-engineer compliance officer author
agent policy *correctly*, see consequences *before* committing, watch behavior
*live*, and *intervene* — without hand-editing JSON or reading a log.

Everything underneath already exists (v0.1 enforcement engine, v0.2 inspector
+ drill). This phase builds the surface on top and the few engine seams it
needs. Where this doc and SPEC.md/ARCHITECTURE.md conflict on the slice's
ethos (minimal deps, structural blindness, nothing-mocked-looks-real,
append-only audit), those win.

## The one sentence

A CISSP-holding compliance officer, who does not write code, opens a browser,
sees People / Capabilities / Policies, edits a policy with dropdowns and a
slider, clicks **Simulate** to see exactly what an agent could and couldn't do
under it, clicks **Publish** (which is itself recorded and reversible), and
watches a live findings feed she can click through to the underlying receipts.

*(As built: the console ships Capabilities / Menu / Policies / Activity. The
**People** screen — roles as directory-synced identities, an org chart from HR
— was NOT built; roles are free-text strings the author types. That identity
layer is a STUB behind the same `KeyRegistry` seam as SSO/OIDC. The input
widgets also differ: the policy editor uses checkboxes, a free-text role
field, and a numeric rate field — no slider; dropdowns appear on the Menu
screen's capability builder. Everything else in the sentence exists and is
tested.)*

## Non-negotiables (inherited + new)

1. **The console is not a new trust hole.** It never sees payload content
   (same structural blindness as the cashier — it only ever touches policies,
   the capability catalog, and receipts, which carry digests + metadata, never
   data). It holds no agent credentials. It is an authoring + viewing surface,
   not an execution path.
2. **Every policy change is itself an audited, signed, append-only event.**
   The thing that governs the agents must be governed the same way the agents
   are. No silent policy edits. No overwrite-in-place. Rollback is a new
   forward event, never a deletion. (Essay 6: "the architecture trains itself,
   but the training process is governed by the architecture.")
3. **Separation of duties is modeled, not assumed.** The admin who *authors*
   policy and the admin who *reviews* audit logs are distinct roles in the
   console, and the highest-impact changes require a second admin's approval.
   The slice can stub the identity provider, but the *separation* must be real
   and enforced, not a comment.
4. **Simulation must be honest.** Simulate runs the *real* validation pipeline
   against the *candidate* policy — not a reimplementation, not an
   approximation — with zero side effects (no ledger row, no chef, no nonce
   consumed). If Simulate and Publish-then-run could ever disagree, the
   feature is a lie and must not ship.
5. **Minimal deps hold.** Stdlib HTTP server + one static HTML/JS page, no web
   framework, no build step, no npm. `cryptography` + `pytest` remain the only
   third-party deps. (ARCHITECTURE anticipates FastAPI "later"; the slice
   proves the surface without taking the dependency. The HTTP handlers are
   written so the swap to FastAPI changes no business logic.)
6. **No LLM anywhere.** Unchanged.

## Engine seams this requires (build these first — they're the real work)

The console is mostly glass. These are the load-bearing changes underneath it.

### A. A pure decision function (enables Simulate)

Today `process_order` validates *and* appends a receipt *and* (on accept)
spawns the chef. Simulation needs the verdict without any of that.

- Extract the five-step pipeline into `cashier/engine.py::evaluate_order(order,
  *, menu, policy_set, store) -> Decision` — a PURE function returning
  `Decision(accepted: bool, reason_code: str | None, scoped_args: dict | None)`.
  No ledger, no signing, no spawn, no nonce mutation.
- `process_order` becomes: call `evaluate_order`, then do the I/O (append
  receipt, mint+sign ticket, spawn) based on the verdict. Behavior identical;
  all existing tests must still pass byte-for-byte.
- Simulate uses a **throwaway nonce store** and a **candidate PolicySet built
  from unsaved form state**, so it never touches real runtime state.

### B. Policy store: versioned, signed, append-only (enables Publish/rollback/audit)

Policies are currently a bare JSON file the form overwrites. That cannot carry
an audit trail or a rollback. Introduce a policy *history*, modeled exactly
like the ledger:

- `authoring/policy_store.py`: an append-only SQLite table
  `policy_versions(seq, json, author, ts, prev_hash, this_hash, sig)` — each
  published policy set is a signed, hash-chained version. CREATE/INSERT/SELECT
  only, same discipline as the ledger (grep-clean of UPDATE/DELETE).
- The *active* policy = the latest version. The engine loads it through the
  existing `load_policy_set` contract (the store materializes the active
  version to the same `policies/*.json` the engine already reads, so the
  enforcement path does not change — the round-trip thesis is preserved).
- **Rollback to version N** = read version N's content, publish it as a *new*
  version N+k with author + reason. History is never rewritten.
- A standalone `verify_policy_history.py` (zero package imports, mirrors
  `verify_ledger.py`) proves the policy chain intact from db + pubkey. So the
  question "who changed what policy when, and is that record trustworthy?" has
  the same cryptographic answer as "what did the agents do?".

### C. A capability catalog with declared metadata (enables the catalog browser
+ friction warnings)

Today there's one capability JSON. The catalog browser and the "are you sure?"
coaching need richer declared metadata to read from — no new engine behavior,
just fuller capability files:

- Extend the capability schema with `risk_class` (already present),
  `recommended_max_rate`, `requires_second_admin: bool`, and a human
  `description`. These are *advisory inputs to the console*, not new
  enforcement (enforcement stays in the cashier). Ship 3–4 example
  capabilities (a low-risk draft, a medium-risk read, a high-risk
  "initiate_payment"-style one that is `requires_second_admin: true`) so the
  catalog and the warnings have something real to show.

## The console itself (the glass)

`console/server.py` — stdlib `http.server`, localhost only, serves one static
page and a small JSON API. `console/static/index.html` (+ a single vanilla-JS
file, no framework). Three screens, matching the essay's mental model.

### Screen 1 — Capabilities (read-only catalog)

The menu, browsable. Each capability shows name, description, declared
inputs/outputs, side effects, scope, risk class, and any
`requires_second_admin` flag. This is what Tanaka picks *from*. No editing —
capabilities come from the platform/engineering, she composes policy over
them.

API: `GET /api/capabilities` → the catalog.

### Screen 2 — Policies (the authoring surface — the heart of it)

The structured editor. NO raw JSON visible by default.

- A list of roles (from the active policy set), each expandable.
- Per role: a multi-select of capabilities **chosen from the catalog**
  (dropdown, not free text), and a **rate-limit slider** per capability/role.
- **Inline coaching, non-punitive** (Essay 4): if a chosen rate exceeds the
  capability's `recommended_max_rate`, or a `requires_second_admin` capability
  is added, the row shows a warning ("Industry-standard max for this is N.
  You've set M.") — a coach, not a blocker.
- **Simulate** button: opens a panel where Tanaka enters (or picks from
  presets) a few sample orders — "an account_manager asks to draft a reply on
  their own thread", "an intern asks the same", "someone asks for
  forward_inbox". The panel shows, per sample, **ALLOW / DENY + the exact
  reason code**, computed by the real pipeline against her *unsaved* candidate
  policy. She iterates until it does what she means.
- **Publish** button: writes a new signed policy version (Screen requires a
  change reason). If any added capability is `requires_second_admin`, Publish
  enters a **pending** state requiring a second admin's approval before it
  becomes active — and the pending request is itself a recorded event.

API:
- `GET /api/policies` → active policy set + version metadata.
- `POST /api/policies/simulate` → `{candidate_policy, sample_orders}` →
  per-order `{allowed, reason_code}`. Pure; no writes.
- `POST /api/policies/publish` → `{candidate_policy, author, reason}` →
  new version (or pending-approval) record. Signed, appended.
- `POST /api/policies/{seq}/approve` → second-admin approval of a pending
  version (must be a *different* author than the publisher; enforced).
- `POST /api/policies/rollback` → `{target_seq, author, reason}` → republishes
  target content as a new version.

### Screen 3 — Activity (the live back office — the inspector, made live)

The inspector's report, rendered as a screen instead of text, over the live
ledger:

- Top line: chain VALID/BROKEN (re-verified on each load), counts fulfilled
  vs rejected.
- The findings list (reuse `inspector.build_report` verbatim — it already
  produces exactly this), severity-sorted, each finding **one click from the
  underlying receipt(s)**: clicking a finding shows the receipt rows it names
  (metadata + digest, never content — the privacy invariant holds on screen
  too).
- A **Run Drill** button that fires the existing adversarial drill against a
  scratch ledger and shows "resisted N/6" with per-probe results — the
  quarterly-test-report artifact, on demand.

API:
- `GET /api/activity` → `inspector.build_report(...)` over the live ledger.
- `GET /api/receipt/{seq}` → one receipt's public fields (metadata + digest).
- `POST /api/drill/run` → runs the drill against a scratch db, returns the
  report.

### Intervention (the levers — modeled honestly)

The essay wants pause/revoke/rollback/re-auth. In the slice these are
expressed through the audited policy path, plus one explicit switch:

- **Pause a capability for a role** = a one-click policy edit (remove the cap)
  published through the normal signed path. Fast, reversible, audited.
- **Rollback** = Screen 2's rollback (above).
- **Kill switch** = a single `paused: true` flag per (role, capability) that
  the cashier checks as a pipeline pre-step → new reason code
  `CAPABILITY_PAUSED`. This is the only new *enforcement* behavior; it gives
  Tanaka an instant "stop this now" that doesn't require re-authoring rates.
- **Out of scope for the slice (flag as STUB):** live session lock, forced
  re-authentication, real-time agent revocation mid-task — these need the
  FastAPI/session layer that isn't built. Model them as named buttons that
  record an intent event but say plainly they're not wired to a live runtime.

## Identity & auth (slice scope — be loud about the mock)

- The console binds to **localhost only** and takes an admin identity from a
  config file mapping `admin_id -> role ∈ {author, reviewer}` plus a shared
  dev token. This is a **MOCK identity provider** — flag it as loudly as the
  MockAttestor. Real deployment swaps in SSO/OIDC behind the same
  `get_current_admin()` seam.
- Separation of duties is enforced on top of this mock: the `simulate`/
  `publish` endpoints require `author`; `approve` requires a `reviewer` who is
  not the publisher; `activity` is readable by both. The *enforcement* is
  real; only the *identity source* is mocked.

## Tests (behavior, exact values — same bar as the rest of the repo)

- `evaluate_order` is pure: same order+policy → same Decision, and calling it
  N times appends ZERO ledger rows / consumes ZERO nonces (assert row count
  and nonce store unchanged).
- `process_order` still produces byte-identical receipts after the refactor
  (regression: existing AT suite passes untouched).
- Simulate API: a candidate policy that adds `intern` → role allowed in sim;
  the real ledger and policy store are unchanged afterward (assert).
- Publish appends a signed policy version; `verify_policy_history.py` returns
  `OK verified=N`; tampering a policy version breaks it at the right seq.
- Second-admin: publishing a `requires_second_admin` capability yields
  *pending*, not active; the enforced policy does NOT change until a *different*
  admin approves; an approve by the *same* admin is rejected.
- Rollback: after rollback to seq K, the active policy equals seq K's content
  AND history length increased by 1 (nothing deleted).
- Kill switch: `paused:true` → cashier returns `CAPABILITY_PAUSED`, no chef
  spawned, chained rejection receipt written; un-pausing restores fulfillment.
- Activity API equals `inspector.build_report` over the same ledger (the
  screen and the CLI can never diverge).
- End-to-end: a `requests`-free stdlib HTTP test starts the server on an
  ephemeral port, drives author→simulate→publish→approve→activity, asserts the
  ledger/policy-history effects.

## Phasing (stop-and-report at each)

1. **Engine seams.** `evaluate_order` extraction (+ regression proof),
   versioned signed `policy_store` + `verify_policy_history.py`, richer
   capability schema, the `paused` kill-switch pipeline step. No UI yet.
   **— DONE (v0.3 phase 1).** `cashier/engine.py::evaluate_order` is pure
   (read-only store; `store.nonce_is_spent` added); `process_order` rebuilt on
   it with all prior behavior preserved (93 tests green). `CAPABILITY_PAUSED`
   live via `Policy.paused_capabilities`. `authoring/policy_store.py` +
   standalone `verify_policy_history.py` shipped. Capability schema gained
   `description`/`recommended_max_rate`/`requires_second_admin`; a high-risk
   `cap.payment.initiate.v1` example added. Inspector knows the new reason
   code. Entry point `sentinel-verify-policy` added.
2. **JSON API, headless.** All endpoints above, driven by tests only (no
   browser). Separation-of-duties + second-admin enforced.
   **— DONE (v0.3 phase 2).** `console/auth.py` (MOCK identity: token→Admin,
   author/reviewer roles), `console/service.py` (all logic + auth, transport-
   free: capabilities/policies/simulate/publish/approve/rollback/activity/
   receipt/run_drill, typed errors), `console/server.py` (stdlib
   single-threaded HTTP over 127.0.0.1, header token, exception→status
   mapping, `build_default_service` + `make_server` + `sentinel-console`).
   Second-admin gate (requires_second_admin → pending until a *different*
   reviewer approves) and separation of duties are enforced and tested;
   Simulate is proven to write nothing; the policy history a session produces
   verifies standalone. 104 tests green.
3. **The glass.** One static page, three screens, vanilla JS against the API.
   Manual run-through + the stdlib e2e test.
   **— DONE (v0.3 phase 3).** `console/static/index.html` (inline CSS) +
   `app.js` (no framework), three screens: Capabilities (catalog browser),
   Policies (structured editor with capability checkboxes, rate input, pause
   toggles, live coaching warnings, Simulate, Publish, Approve), Activity
   (chain status, findings with click-through to receipts, Run Drill). Served
   by `server.py` from 127.0.0.1 with a strict CSP (`default-src 'none'`,
   `script-src 'self'`, no external origins, no inline script), nosniff /
   frame-deny / no-referrer headers, and NO CORS. The page loads without a
   token (it's what lets the operator enter one); every /api call still
   requires it. Tests prove the page is self-contained (zero external URLs).
   108 tests green; live run-through verified author→publish(pending)→
   reviewer-approve over real HTTP.

## Security posture (answering "isn't a server a risk for an air-gapped slice?")

The console is the highest-value target, so its design is defensive by
construction:

- **Control plane, not data plane.** Nothing in the enforcement/data path
  depends on the console; turn it off and agents still run and are governed.
  It is optional.
- **Structurally blind to content.** Like the cashier, it can only reach
  receipts (digests + metadata) and policies. A fully compromised console
  cannot read one payload byte — the data isn't reachable from where it sits.
- **Its one power — authoring — is bounded.** Every change is signed,
  append-only, externally verifiable, and second-admin-gated for sensitive
  capabilities. It cannot silently widen permissions.
- **Localhost, self-contained, operator-owned.** Binds loopback only (warns
  otherwise), loads zero external resources, strict CSP, token in a header
  (not a cookie) so cross-origin pages can't forge calls. It is the Settings
  app, not a SaaS — it runs inside the operator's trust boundary.
- **Replaces an existing, *worse* surface.** Hand-edited policy JSON was
  already attackable, just invisibly. This makes authoring legible and gated.

## What this explicitly does NOT make real (unchanged stubs)

TEE attestation, microVM isolation, provenance-signed kitchen, real SSO,
live session/runtime revocation, anomaly detection with a learned baseline,
the signed continuously-updated curriculum, external chain anchoring,
multi-tenant deployment. The console makes the *operator control loop* real on
top of the existing engine; it does not change what's mocked below it.

## Why this is the right next build (one paragraph)

The microVM and attestation are commodities you buy. The enforcement engine
already exists. The defensible product — the reason a regulated institution
picks this over raw confidential-computing primitives — is precisely that a
non-engineer can author correct policy, prove what changed and why, and read
the evidence. That is this console. Until it exists, the honest answer to "can
your compliance officer run this?" is no, and the thesis's own argument says
that's the difference between a deployable product and a developer tool.
