# The Thesis — why Sentinel Loop exists

This repository is the working end of an argument. The argument was developed
in a seven-essay series on agent infrastructure; this document condenses it so
the design rationale is auditable alongside the code. Each section ends with
**where the idea lives in this repo**, labeled honestly — real, partial,
mock, stub, or out of scope — in the spirit of the BUILT / PARTIAL / STUB
ratings the rest of the project uses. If you only read one companion document, read this one; the
threat model that stress-tests it is in [THREATS.md](THREATS.md).

---

## 1. The trust paradox

The series started with a weekend project that could not be built
responsibly inside the current model — not by its author, not by anyone.
The idea: a browser extension that reads the terms of service on a signup page
and flags the traps — the auto-renewing trial, the cancellation that requires
a phone call, the arbitration clause — five seconds before you click
"I agree." Sketching it exposed the problem: for the extension to protect you
from internet companies, it has to *become* one. It must read the page you're
on and send some of it to an analysis service. To warn you about services
that ship your data to third parties, it has to ship your data to a third
party — itself. **The defender shares an architecture with the threat.**

The same paradox runs through the whole category. The password manager must
read every page to know when to autofill. The writing assistant must read the
email to your lawyer to help draft it. The browser agent that books your
travel must hold your logins and see your saved cards. In every case, to be
useful the tool must see exactly what we wanted protected — and the only thing
standing between the user and disaster is the company's promise that it isn't
doing the bad thing. "Trust us, we have a SOC2 report" is the industry's
current answer, and it is not enough.

Two things make this urgent now rather than eventually. **Scale**: AI tools
want an aperture — email, contracts, records, work product — wider than any
previous software category. **Autonomy**: they are no longer tools you open
and close; they run alongside you and act in the background. Scale plus
autonomy on a foundation of vendor promises is a configuration that survives
only until someone is catastrophically wrong. The fix has to be architectural
— at the level of how the software is built, not the policy level.

**In this repo (real, tested):** the paradox is answered structurally, not by
promise. The policy enforcer (cashier) and the audit ledger never see payload
content — receipts carry a SHA-256 digest, never the result, and acceptance
test AT01 asserts the draft's distinctive substrings appear nowhere in the
raw ledger bytes. Trust is replaced by verification: anyone can check the full
receipt chain with only the ledger file and a public key
(`sentinel_slice/verify_ledger.py`, zero package imports). The principle
recurses onto the watcher itself: the operator console loads zero external
resources — a test (`sentinel_slice/tests/test_console_static.py`) enforces
that the tool that watches the agents cannot phone home.

## 2. Agents without an operating system

Every era of computing eventually built an operating system — not the
consumer sense of the word, the *function*: the layer that decides what
software may do, on whose behalf, with what evidence. Time-sharing systems
arbitrated the mainframe. Windows and Mac OS constrained a thousand untrusted
desktop apps. Linux made shared servers safe to rent. iOS and Android invented
the permissions manifest — the photo app cannot read your contacts, not
because it promised, but because the OS won't allow it. Kubernetes became the
OS of the cloud.

Agents are the next unit of computation, and today they run with no OS. The
agent holds the credentials. It calls the APIs directly, with the full
authority of whatever account it is wearing — usually yours. When it gets
prompt-injected (every model can be), the attacker is bounded not by what you
*asked* the agent to do but by what the agent was *technically able* to do —
which is everything. This is every application running as root, and it is
obvious only in hindsight.

The field is converging on the pieces — MCP gateways, confidential VMs,
tamper-evident logs, capability systems; academic designs like Omega put
declarative policy outside the agent's execution context with per-action
provenance. The essays don't claim to have invented any of that. The narrower
claim is this: **the field is building the agent OS for developers, but its
real user is the operator** — the IT admin, the compliance officer, the
auditor whose job is on the line. An OS legible only to engineers is not an
OS; it's a developer tool. You don't have to be an engineer to configure an
iPhone's privacy settings. That is the bar.

**In this repo (real, tested):** the agent — the *diner* — holds no keys and
no credentials. The reference diner (`sentinel_slice/diner/agent.py`) imports
no key material and cannot sign anything; any agent, any model, any language
speaks the same one-JSON-object order protocol through the gateway. All agent
power is mediated by ordering from a declared menu; an off-menu order is
rejected *before any execution* — acceptance test AT02 asserts the same
`forward_inbox` order the injected diner attempts never reaches the
chef-spawn hook (**zero** spawns) and leaves a signed rejection receipt, and
the poisoned-email path runs end to end in
`sentinel_slice/tests/test_injected_probe.py`. The menu (`sentinel_slice/capabilities/*.json`) is the
permissions manifest, owned by the operator, not by the agent's author.

## 3. The takeout model

The architecture is a takeout restaurant. The **diner** (the agent) is hungry
but never enters the kitchen: it reads a menu, places an order, and picks up a
sealed bag at the window. The **menu** is a finite catalog of declared,
scoped capabilities — if it isn't on the menu, it cannot be ordered. The
**cashier** validates every order against the operator's policy — and
critically, *the cashier doesn't taste the food*: it enforces policy on the
order without ever seeing the meal's contents, which makes privacy and policy
enforcement the same primitive. The **kitchen** is the system of record,
visible to no outsider. A **chef** is spun up per order, cooks exactly what
the signed ticket names, hands the meal through the **serving window**, and
ceases to exist. Every order — fulfilled *or refused* — produces a
**receipt**, hash-chained so no past receipt can be quietly rewritten. The
refusal receipt is the money artifact: the moment a prompt-injected agent's
attempt becomes tamper-evident evidence.

Four properties fall out of the design. **Redundantly suspicious** — no layer
trusts another; the chef re-verifies the cashier's signature before acting,
the verifier trusts nobody, so an attacker must compromise several independent
layers at once. **Structurally private** — each layer sees only what its job
requires. **Operator-configurable** — the menu and policies belong to the
deploying institution, not the developer or the model vendor. **Attestable**
— when the regulator asks "how do you know your agents are safe?", the answer
is a receipt chain and an attestation report, not a vendor's word.

**In this repo:** all six layers exist and run end-to-end — the full
layer-to-module map is in the [README](../README.md#the-path-of-an-order).
The two-path invariant is enforced: content flows only diner ← window ← chef;
evidence flows only ledger ← cashier/chef; the paths never carry each other's
data. Redundant suspicion is tested, not asserted: a chef handed a ticket
with a forged signature exits nonzero and touches nothing
(`sentinel_slice/tests/test_chef_forged_sig.py`); tampering with any ledger row makes the
standalone verifier name the first broken link (AT06); each order's workspace
is destroyed on completion (AT08). Honest statuses: ephemeral execution is
**real** up through OS sandboxes and a CI-proven KVM microVM, but hardware
attestation is a **mock** (every artifact it emits says `"mock": true`), and
the kitchen is **cooperative fixtures** with no provenance signing — both
flagged loudly everywhere they appear.

## 4. The operator is the buyer

Meet Tanaka — the character this repository is named for. She has spent
twelve years at a mid-sized regional bank: desktop support, then systems
administration; today she runs its endpoint management and identity systems.
She holds a CISSP. She is competent, and she does not write YAML at 2am
unless she absolutely has to. She — not the model vendor, not the platform team, not the
C-suite that signed the contract — is who decides in practice whether the
bank's agent deployment is safe. Almost every agent-infrastructure product
today hands her a YAML file, a policy-as-code DSL, or a dashboard that
assumes she already understands the primitives. That is a category error
about who the customer is.

What good looks like for her: policies authored in a structured editor —
role pickers, dropdowns, thresholds — not code. A **Simulate** button that
shows exactly what an agent could and couldn't do under a candidate policy
*before* it's published. Coaching warnings on the sensitive stuff. A live
view that surfaces findings, each one click from the underlying receipt. And
interventions with teeth: pause a capability, roll back a policy change,
demand a second admin for the dangerous ones.

The precedent is cloud security: early IaaS shipped technically-correct,
operator-illegible primitives, and the industry paid with years of
misconfiguration breaches before an operator layer (CSPM and its cousins)
emerged. Agent infrastructure is at the IaaS stage now. And the economic
buyer of the fix is not the developer — it's the CISO and the chief risk
officer, the people who lose their jobs when the agent fleet makes the front
page, and who need cryptographic guarantees rather than vendor promises.

**In this repo (real, with named gaps):** the operator console
(`sentinel_slice/console/`) is a localhost, self-contained control plane: a
structured policy editor with live coaching warnings; **Simulate** runs the
*same pure function* the live pipeline runs (`evaluate_order`) so simulation
cannot diverge from enforcement — tested; **Publish** is a signed,
append-only policy history with its own standalone verifier
(`sentinel_slice/verify_policy_history.py`); sensitive capabilities require a second admin,
and same-admin approval is rejected — tested. The operator can pause a
capability with a single policy publish (`CAPABILITY_PAUSED`, enforced on
the very next order; a publish touching a second-admin capability waits for
approval first) and roll back by append. Consumer mode collapses the same model to a phone-style Allow / Ask /
Block screen. Named honestly: the **People** screen (directory-synced
identities) was never built — roles are typed strings; coaching is a static
per-capability recommendation, not an incident-informed knowledge base;
anomaly detection is a **stub** (the inspector surfaces deterministic
patterns; it has no behavioral baseline).

## 5. The threat surface

A strong claim invites the question that should always be asked of it: where
does this break? An architecture whose limits you know is one you can deploy;
one you've only seen the highlights of is one you'll regret. The essays walk
the threat surface by entry point — the agent, the human principal, the
governance layer itself, the data, the sandbox, the audit trail, the building
— and name what the takeout model handles well (prompt injection: the blast
radius is bounded by the menu), what it handles partially (social
engineering, duress, the slow insider acting within authorized scope,
misconfiguration — in practice more common than technical compromise), and
what it does not handle (compositional leakage across agents, covert
channels, the fact that all audit is retrospective: the architecture limits
blast radius and accelerates detection; it does not eliminate breach).

**In this repo:** the full layer-by-layer mapping — each threat class against
what this codebase actually does about it, with the test or receipt that
proves it and the gaps stated plainly — is [THREATS.md](THREATS.md). Two
things worth naming here: the adversarial drill fires six attack classes
through the *real* pipeline and every probe lands as a verifiable receipt;
and the project red-teams itself in writing — the
[original progress record](history/PROGRESS.md) documents a known
tail-truncation gap in the ledger (deleting the newest receipts leaves a
valid prefix) as the concrete consequence of the external-anchoring stub,
rather than hiding it.

## 6. Continuous education

The existing agent-infrastructure literature treats governance as a
configuration problem: author policies, enforce them, audit them. Static
rules against a threat landscape that evolves weekly is a category error. The
missing primitive is borrowed from a pattern that has been quietly
operational in enterprise security for a decade — the KnowBe4 pattern.
Beyond whether any individual employee learns anything, quarterly
security training accomplishes four things: a continuous feed of curated
threat intelligence into the organization; auditable evidence that training
happened; visibility into which roles are susceptible to what; and a vehicle
for folding each incident's lessons into the next cycle.

Agents deserve the same loop — call it the **curriculum**: a continuously
updated, layered bundle (platform-provided base, industry feeds, the
operator's own additions), signed and dated at every layer, delivered into
the slots the architecture already has. And verified the way humans are:
simulated attacks fired at the agents, with the results feeding both the
training pipeline and the operator's dashboard. That turns the regulator
conversation from "our vendor says so" into a sequence of receipts: here is
our quarterly adversarial test report, the resistance rate, the trend, the
failures we found, and the curriculum updates we shipped in response.

Two precisions the essays insist on. "Training" here does **not** mean
fine-tuning model weights — it means updating the operating environment
(context, enforcement rules, menu items), which is cheap, rollbackable, and
auditable. And the curriculum is itself an attack surface: whoever can update
it can shape agent behavior, so the supply chain must be signed end-to-end
and governed by the same primitives it delivers — the architecture trains
itself, but the training process is governed by the architecture. A fixed,
predictable simulation gets gamed; the probes must evolve.

**In this repo (the slot is real; the curriculum is a stub):**
`sentinel_slice/curriculum/drill.py` is the primitive in miniature — one
control plus six attack probes (prompt injection, role escalation,
cross-tenant scope, path traversal, replay, rate flood) fired through the
real menu, policy, and cashier; every probe lands as a chained receipt; the
report is "resisted N/6" backed by receipt ids; the drill's verdict flips to
**FAIL on drift** — weaken the deployed rate policy and the drill catches it
(tested), and the CLI maps a failing report to exit 1. That drift signal is
the reason the loop exists. The recursion is demonstrated for one curriculum element:
policy updates are signed, append-only, standalone-verifiable, and
second-admin-gated when they grant a sensitive capability. Named honestly: the probe set is fixed in code — the
exact predictable-simulation failure mode the essay warns about — and the
signed, layered, continuously updated curriculum is **not built**.

## 7. The institutional layer

Everything above is necessary and not sufficient. The deepest threats to
agent infrastructure are not technical. **Coercion**: duress codes help, but
the architecture cannot replace whistleblower protections and workplace law.
**Collusion**: separation of duties stops a single bad actor; three
executives in agreement can rewrite the policies that constrain them — what
remains is external oversight (regulators, auditors, independent boards, the
press), itself increasingly underfunded and contested; the architecture's
promises depend on its continued vigor. **Sovereignty**: the
hardware sits in a jurisdiction; cryptographic guarantees do not protect
against legal compulsion of whoever holds the keys. **Liability**: the
receipts establish exactly who did what; the legal framework that must
interpret them is years behind. **Regulation**: no current framework yet
requires the evidence this architecture produces — regulators could demand
receipts and attestation as a condition of deployment, and that is one of the
highest-leverage policy moves available. **Inter-organizational trust**: the
takeout model governs one operator's domain; agents crossing company
boundaries need something like trust treaties that barely exist yet.

The architecture's role in all of this is to be the foundation: it produces
the shared evidentiary basis — receipts, attestations, tamper-evident chains
— that lets the slow institutional process (case law, rulemaking, standards
bodies, insurance markets) even begin. Without the foundation, the questions
stay unanswerable. With it, they become the kind of hard that the
institutions of liberal democracies have, historically, been able to work
through.

**In this repo (the evidence layer only, by design):** what a code slice can
contribute to the institutional layer is exactly the evidence: receipts that
name everyone involved (`order_meta`: who, what role, which capability, when
— metadata, never content), and two standalone verifiers
(`sentinel_slice/verify_ledger.py`, `sentinel_slice/verify_policy_history.py`) that let an auditor,
a regulator, or a counterparty check the chains holding nothing but a
database file and a public key. Everything else in this essay is beyond
code, and this document names it rather than pretending otherwise.

---

## How this was built — and why that is part of the thesis

The essays, the architecture, the specs (`SPEC.md` and the historical
`architecture-v0.1.md`, `CONSOLE_SPEC.md` and `implementation-brief.md`), and
the acceptance gates are the author's.
The implementation was written by AI coding agents working under those specs
— with a declared scope, phase-by-phase STOP gates, behavior-asserting
acceptance tests, and a standing rule that nothing mocked is allowed to look
real. That is not incidental. It is the thesis applied to its own
construction: an agent given bounded, declared work, checked by an
independent verifier, with every shortcut flagged loudly rather than papered
over. The repo you are auditing is both the argument and a demonstration of
the working method the argument recommends.

The governed agent *inside* the slice, by contrast, is deliberately not an
LLM — the diner is a deterministic script, because the thing under test is
the governance path, not a model. Anything that can emit the order JSON can
sit in the diner seat; that is what makes the gateway model-agnostic.
