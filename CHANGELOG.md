# Changelog

All notable changes to Sentinel Loop, in order. Dates are UTC, taken from the
git history. This is the terse version-by-version summary. The progress record
from the original build is preserved in `docs/history/PROGRESS.md`.

## [Unreleased]

### 2026-07-06 — the thesis, in the repo

- `docs/THESIS.md` — the seven-essay argument the project is built from (trust
  paradox → agent OS → takeout model → operator-as-buyer → threat surface →
  continuous curriculum → institutional layer), condensed, each essay mapped
  to where it lives in the code with honest real/partial/stub labels.
- `docs/THREATS.md` — the Essay 5 threat model applied to this codebase: every
  threat class by entry point, with the test that proves the defense or the
  plain statement that there isn't one.
- README: "why it exists" up top; corrected the env-gated-proofs sentence
  (GUI + installer proofs run on a dev box, not in CI — only the OS-sandbox
  and microVM proofs run in CI).
- `cashier/engine.py` docstrings: "five-step" → "six-step" (stale since the
  v0.3 kill switch made it six); `docs/history/CONSOLE_SPEC.md` now says plainly
  that the People screen was never built.
- `docs/history/PROGRESS.md` de-staled: the header test count (249/8 → 271/16, with the
  gated-test breakdown), and the closing out-of-scope list now carries
  per-item current status (the console, multiple capabilities, and the KVM
  microVM have long since been built; the rest remain stubs).

### 2026-06-15 — hardening and CI proofs (on top of 0.15.0, not yet its own version bump)

- Console identity replaced with real Ed25519 signed-request authentication
  (`console/signed_auth.py`), retiring the earlier mock dev-token table.
- `LinuxSeccompSandbox` (seccomp + Landlock) and `MacSandbox` (Seatbelt) added
  as in-process OS sandbox peers to the existing Windows AppContainer backend,
  each proven in CI on its own runner.
- `MicroVmSandbox` — the chef running inside a real KVM virtual machine via
  QEMU, proven in CI (`microvm-isolation` workflow) on a stock Linux runner.
- SPDX Apache-2.0 headers added across the Python source; `NOTICE` refreshed.

## [0.15.0] — 2026-06-11

`AppleVmSandbox`: a macOS containment backend via Apple's `container` tool
(WWDC 2025), giving each order its own lightweight VM on
Virtualization.framework. Command construction is unit-tested exactly; not
run here for real (no Mac on the dev box).

## [0.14.0] — 2026-06-11

The Windows installer: `installer.py` (per-user install/uninstall, no admin),
`build_installer.py` (`dist/SentinelLoop-Setup-<ver>.zip`), a Start Menu
shortcut, and a real Add/Remove Programs entry. Proven end to end on a
Windows box. The bundle is unsigned — SmartScreen warns on first run.

## [0.13.0] — 2026-06-11

`sentinel-app`: the tkinter desktop shell (Connect / Permissions / Activity)
that lets a non-technical user wire Sentinel into an MCP host with one click,
preserving every other entry in that host's config.

## [0.12.0] — 2026-06-11

OS-enforced containment on a real machine. `Receipt.containment` records
which sandbox actually ran an order. `AppContainerSandbox` runs the chef in a
Windows AppContainer with zero installed capabilities, proven live.

## [0.11.0] — 2026-06-11

On-device approval dialog (`consumer/native.py`, `NativeApprover`) for
`sentinel-mcp --confirm`, since an MCP server's stdio is the JSON-RPC channel
and has no terminal to prompt on. Fails closed with no display.

## [0.10.0] — 2026-06-11

Installable app: `sentinel-init` creates a per-user app home
(`%APPDATA%\SentinelLoop` and platform equivalents); all entry points resolve
keys, ledger, and permissions through it instead of the checkout or cwd.

## [0.9.0] — 2026-06-10

`mcp_gateway.py`: Sentinel as a minimal MCP server. Every `tools/call` becomes
a governed, receipted order — the two things plain MCP doesn't check on its
own (per-call scope/rate/replay, and a verifiable receipt on every refusal).

## [0.8.0] — 2026-06-10

Template behaviors: a non-technical operator can author a whole new text
behavior as a message template (`string.Template`, safe substitution only —
no code, no attribute access), not just configure an existing one.

## [0.7.0] — 2026-06-10

No-code menu curation. Splits a menu item into a behavior (engineer-authored,
once) and a capability (operator-composed, no code). Console gains a Menu
screen to add, enable, disable, or remove capabilities.

## [0.6.0] — 2026-06-10

Personal permissions: a phone-style Allow / Ask / Block screen per
capability, no JSON. Block auto-denies silently and still leaves a receipt.

## [0.5.0] — 2026-06-10

Pluggable capabilities: the chef stops being hardcoded to email and dispatches
on `capability_id` to a per-capability handler. Ships three capabilities
(`draft_reply`, `docs_summarize`, `payment_request`).

## [0.4.0] — 2026-06-10

Consumer mode: human-in-the-loop approval for high-stakes actions on a
personal machine. Also introduces the swappable `Sandbox` interface and a
hardened `ContainerSandbox` (optionally under gVisor).

## [0.3.0] — 2026-06-10

The Tanaka operator console: a pure `evaluate_order` engine seam, a signed
append-only policy history, a headless JSON API with author/reviewer
separation of duties, and a self-contained localhost UI.

## [0.2.0] — 2026-06-10

The back office: receipts gain `order_meta` (who/what/when), `inspector.py`
gives a chain-validated day report, and `curriculum/drill.py` fires a fixed
adversarial probe suite through the real pipeline.

## [0.1.0] — 2026-06-09

Initial vertical slice: spine types, the hash-chained signed ledger and its
standalone verifier, the cashier's five-step validation pipeline, the
ephemeral chef, and the scripted diner. All 10 SPEC acceptance tests pass.
