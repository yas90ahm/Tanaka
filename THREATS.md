# Threat Surface — what this slice defends, and what it honestly does not

The essays' rule: an architecture you understand the limits of is one you can
deploy; an architecture you've only seen the highlights of is one you'll
regret. This document walks the threat surface of the takeout model the way
an adversary would — by entry point — and maps every threat class to what
**this codebase** actually does about it, with the test or receipt that
proves it. It is the Essay 5 stress-test applied to the slice itself.

Labels, used strictly:

- **HANDLED** — enforced by this code and asserted by a test in this repo.
- **PARTIAL** — a real mechanism exists here, but it covers less than the
  full threat class; the shortfall is stated.
- **STUB** — a designed seam exists (swapping it in changes no type
  signature), but the defense itself is not built.
- **NOT MODELED** — absent from the slice; named here so nobody mistakes
  silence for coverage.

---

## Entry point: the diner (the agent is the threat)

**Prompt injection — HANDLED (for what a broker can handle).** The agent
holds no keys and no credentials; a fully injected agent can still only place
orders from the menu. The canonical probe is built in: a poisoned fixture
email instructs the agent to forward the inbox to an attacker; the injected
diner attempts `forward_inbox`; the cashier rejects it **before any
execution** — acceptance test AT02 asserts the same off-menu order never
reaches the chef-spawn hook (zero spawns) and a chained `OFF_MENU` rejection
receipt is appended, and the full poisoned-fixture round trip through the
injected diner is asserted in `sentinel_slice/tests/test_injected_probe.py`
(rejection receipted, no ticket minted, no draft ever written). The same
class is fired
on demand by the drill (`sentinel_slice/curriculum/drill.py`). Honest boundary: the
"injection" here is a deterministic script reading a poisoned fixture — it
proves the governance path bounds an injected agent; it says nothing about
any particular model's susceptibility (no LLM is in the slice, by design).

**Weaponizing a legitimate capability — PARTIAL.** If a menu item is
dangerous when invoked by a confused agent, the menu must carry the friction.
The primitives exist and are tested: `requires_user_confirmation` (the
payment capability pops an on-device Allow/Ask/Block gate; denial lands as a
signed `USER_DENIED` receipt), `requires_second_admin` (publishing a policy
that grants it needs a different reviewer), and per-role rate limits. Not
built: out-of-band verification, hardware-key confirmation, or two-party
approval *per order* (second-admin gating is at policy-publish time, not
order time).

**Malformed / garbage intake — HANDLED.** An order that fails to parse is
refused *and still receipted* under a gateway-assigned identity
(`principal: gateway:unadmitted`, reason `MALFORMED_ORDER`), so a probe
flooding the counter cannot slip beneath the audit trail; the raw bytes are
never stored (privacy invariant holds). Residual: the MCP gateway's
pre-order intake errors (unknown tool, non-object arguments) return to the
caller but are not yet receipted — flagged in PROGRESS.md, not fixed.

**Compositional information leakage — NOT MODELED.** Two narrowly-scoped
agents whose combined outputs reveal what neither should. The slice governs
one order at a time and has no notion of cross-agent correlation. The essays
call this a mostly-open research problem; this repo does not address it.

## Entry point: the principal (the human is the threat)

**Social engineering of the principal — NOT MODELED.** The essays' answer is
the agent as *witness* — noticing that the "CFO" was added to contacts four
minutes ago and pausing. That requires judgment in the diner seat, which the
no-LLM constraint deliberately excludes from this slice. What exists is the
static version: high-stakes capabilities can be forced through a human
confirmation gate. The drill has no social-engineering probe for the same
reason — its probes test structural refusals, not judgment.

**Duress — NOT MODELED.** No duress codes, no coerced-authorization
signaling. The essays themselves class duress as mitigated-not-solved even
in the full architecture; the slice does not model it at all.

**The slow insider within authorized scope — PARTIAL, mostly deferred.** The
raw material exists: every action leaves a receipt naming principal, role,
capability, and time; rate limits bound velocity; the inspector reports
per-principal patterns across every receipt in the chain. But detection of
*slow* abuse
needs a behavioral baseline and anomaly model, and that layer is an explicit
STUB — the inspector does pattern *surfacing* (deterministic rules, fixed
severities), not anomaly *detection*. All audit is retrospective; the essays
say this plainly and so does this repo.

## Entry point: the cashier (the governance layer is the threat)

**Technical compromise of the enforcer — PARTIAL / STUB.** The defense the
essays prescribe is hardware-attested execution; here, attestation is a
**MOCK** — `MockAttestor` proves the receipt has an attestation *slot*, every
artifact it emits says `"mock": true`, and nothing about the execution
environment is actually proven. What is real is defense-in-depth around the
execution layer (see "the chef" below) and structural blindness: even a fully
compromised cashier or console never held payload content to leak.

**Misconfiguration — the essays' most-likely failure, and the product's
actual job — PARTIAL.** The console exists precisely to make the wrong
policy hard to write: a structured editor (no hand-edited JSON), live
coaching warnings against per-capability recommended maximums, **Simulate**
that runs the same pure `evaluate_order` function the live path runs (it
cannot diverge — tested), publish-as-signed-append (rollback is a new
version, never a rewrite), a `CAPABILITY_PAUSED` kill switch, and
second-admin approval for sensitive grants. Shortfalls, named: coaching is a
static recommendation, not an incident-informed knowledge base; there is no
policy-templates library; roles are free-text strings (no directory sync —
the "People" layer was not built).

**The complicit admin — PARTIAL.** Separation of duties is real and
enforced: the author who publishes cannot approve their own sensitive
change; a different reviewer must, and same-admin or wrong-role approvals
are rejected (tested). Admin identity is real Ed25519 possession-proof per
request — no shared secrets. Named limits: colluding admins defeat
separation (the essays place that defense at the organizational layer, not
the technical one); admin key rotation/revocation has no story yet —
federation to a directory (SSO/OIDC) is the stub that would carry it.

## Entry point: the kitchen (the data is the threat)

**Tampered store / poisoned upstream feeds — STUB.** The architecture
assumes the kitchen is honest; the essays say that assumption is wrong in
general and demand cryptographic honesty (signed records, chain-of-custody).
This slice's kitchen is **cooperative fixtures** — no provenance, no
integrity signing, assumed well-formed. The production swap is named
(fixture mailbox → provenance-signed store) and unbuilt. Note the poisoned
fixture email is *deliberately* poisoned — it is the injection probe, not a
provenance defense.

**Cross-tenant reach inside the kitchen — HANDLED.** A crafted
`thread_id="user.kenji/../victim/secret"` once passed both guards; the
project's own adversarial review caught it (review #1) and both layers now
reject independently: the cashier refuses any non-single-segment resource id
(`OUT_OF_SCOPE`; a later red-team pass added the control-character/NUL
rejection), and the chef confines reads to the owner's directory
(`sentinel_slice/tests/test_fix_scope_traversal.py`). On Linux, Landlock adds a
kernel-enforced allow-list outside the whole fixtures root
(defense-in-depth, CI-proven).

**Covert channels (timing, resource, error-message leakage) — NOT MODELED.**
The essays call this an open research area where the architecture raises
cost without eliminating exfiltration. Nothing in this slice addresses it.

## Entry point: the chef (the sandbox is the threat)

**Sandbox escape — PARTIAL, honestly laddered.** The default backend is a
fresh subprocess with a network-free import closure (AT07) and a destroyed
workspace (AT08) — that is a *contract*, and the docs refuse to call it a
guarantee: it does not contain a hostile chef. The real rungs above it are
built and CI-proven, each on its own platform: Windows AppContainer (OS
denies network and foreign reads), Linux seccomp+Landlock (kernel denies
sockets and out-of-list filesystem access), macOS Seatbelt (denies network
and stray writes; read-confinement honestly weaker), a hardened OCI
container with gVisor, and a **KVM microVM** — the chef in a real virtual
machine with its own kernel, byte-identical output to the subprocess
backend. The ceiling is named: a VM is not a TEE — no hide-from-host, no
hardware attestation; that frontier remains the mock. Crucially, **every
receipt appended since v0.12 records which containment class actually ran**,
hash-bound — forging a stronger claim into a stored row breaks verification
at that seq (`sentinel_slice/tests/test_containment_receipt.py`). Legacy
rows carry no containment claim, and the hash rule binds a row's entire key
set, so splicing a new key into an old row breaks the chain
(`sentinel_slice/tests/test_receipt_order_meta.py`).

**A forged ticket reaching the chef — HANDLED.** The chef verifies the
cashier's Ed25519 signature *before any side effect* — inside the subprocess,
and inside the VM on the microVM backend. Forged signature → nonzero exit,
nothing touched (`sentinel_slice/tests/test_chef_forged_sig.py`).

**Sensitive-by-design output — PARTIAL.** When the order is "summarize this
confidential document," the output is *supposed* to contain confidential
material — output filtering cannot help. The defenses that exist here are
structural: the output goes only to the diner through the serving window
(never to the ledger — AT01), reads are scoped to the acting principal's own
resources, and high-risk capabilities can require confirmation. Menu-design
discipline — pairing sensitive items with stricter authorization — is the
operator's job; the console's risk classes and coaching are the start of
that, not the end.

## Entry point: the receipts (the audit layer is the threat)

**Receipt tampering — HANDLED.** Every receipt is hash-chained (genesis
`sha256(b"GENESIS")`) and Ed25519-signed; the standalone verifier recomputes
everything from the db file and a public key alone. Flip one byte in row 50
of a 100-receipt chain and the verifier exits 1 naming seq 50 (AT06). The
same construction protects policy history
(`sentinel_slice/verify_policy_history.py`).

**Tail truncation — KNOWN GAP, self-reported.** The chain proves no row was
altered and no earlier row removed — but deleting the *newest* receipts
leaves a valid prefix the verifier still accepts. An attacker with DB write
access could quietly drop the latest rejection receipt. This is the concrete
consequence of the external-anchoring STUB (co-signing head+count to an
external witness), documented in PROGRESS.md rather than discovered by a
reviewer.

**Audit overwhelm — PARTIAL.** The inspector emits a short, deterministic
findings report (off-menu attempts, replays, rate pressure, execution
failures), not a log firehose, and every rejection-pattern finding links to
the receipts behind it (the mock-attestation reminder is the one finding
that names none). But
tuning signal-to-noise against a real fleet needs the behavioral baseline
that is not built.

**All audit is retrospective — ACKNOWLEDGED.** The inspector finds attacks
after the receipts exist. The architecture's honest promise is bounded blast
radius and faster detection, not breach elimination. This sentence appears
in the repo's own docs because the essays require it to.

## Entry point: the building (meta-threats)

**Catastrophic loss, legal compulsion, sovereignty — OUT OF SCOPE, named.**
Disaster recovery for the ledger, subpoena of the signing keys, the
jurisdiction the kitchen physically sits in, vendor-exit for the receipts —
these are institutional-layer problems (Essay 7; THESIS.md §7) that code
constrains but cannot solve. The slice runs inside one operator's trust
boundary on one machine; nothing here should be read as addressing the
geopolitical version of the problem.

---

## What has actually been adversarially exercised

- A multi-agent red-team review of the slice produced 10 findings, all on
  failure/adversarial paths; all 10 fixed with regression tests
  (`sentinel_slice/tests/test_fix_*.py` — cross-tenant traversal, silent
  no-receipt acceptance, exit-code robustness). PROGRESS.md documents the
  pass unsoftened, grouped into those three fix areas.
- The adversarial drill fires 6 attack classes through the real pipeline on
  demand; each probe lands as a verifiable receipt; the drill's verdict
  flips to FAIL on any drift, including a quietly weakened policy (tested);
  the CLI maps a failing report to exit 1.
- The tail-truncation gap above was found by the project's own red-team
  pass and published in PROGRESS.md.
- Not yet done, and worth stating: no external (non-author) security review,
  no fuzzing of the order/ticket parsers, no side-channel analysis. The
  console's request-signing scheme is hand-rolled (canonical string +
  Ed25519 + freshness window) and pinned by tests, but it has not had
  independent cryptographic review.
