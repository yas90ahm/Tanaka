# Repository audit

Audit date: 17 July 2026  
Repository: `yas90ahm/Tanaka`  
Audited branch: `repo-cleanup`  
Default branch: `master`  
Audit scope: documentation and recommendations only. No files were deleted, moved or rewritten.

## 1. Repository summary

Tanaka contains Sentinel Loop, a Python proof of concept for controlling what an AI agent is allowed to do. The agent chooses from a fixed menu, receives a short-lived signed ticket, performs work through a containment backend and writes a signed receipt. The repository includes a local console, MCP gateway, policy authoring, several operating-system containment paths and a deterministic demo ledger.

The code and validation are more current than the root architecture and build documents. The public repository name is Tanaka while package names, commands and documentation mostly say Sentinel Loop. That naming relationship should be explained once and used consistently.

## 2. Current structure

The repository contains 164 tracked files.

| Path | Purpose | Assessment |
| --- | --- | --- |
| `sentinel_slice/` | Application, policy, ticket, execution, receipt, console, MCP and tests | Core source; retain |
| `microvm/` | KVM/QEMU rootfs and helper inputs | Current containment option; retain |
| `.github/workflows/` | Main CI, sandbox checks and microVM checks | Active; retain |
| Root Markdown files | README, specification, architecture, console, progress, thesis and threats | Valuable but mixes current reference and build history |
| `ledger.db` | Small committed demo/acceptance ledger | Intentional evidence artifact; retain |
| `sentinel_slice/keys/cashier_ed25519_public.pem` | Public verification key | Intentional package data; retain |
| `Dockerfile`, installer files and package metadata | Local delivery and build surfaces | Retain |

The package exposes multiple command-line entry points for setup, execution, verification, gateway, console, MCP, inspection and policy authoring, plus a desktop entry point.

## 3. Identified projects

This is one system with six connected areas:

1. Policy and capability definition.
2. Signed ticket issuance and replay/rate controls.
3. Contained execution through subprocess, container and OS/VM-specific backends.
4. Signed, hash-chained receipt storage and verification.
5. A local operator console and consumer approval experience.
6. MCP and gateway integration for agents.

The repository is explicit that trusted-execution-environment attestation remains mocked. That boundary should stay visible in current documentation.

## 4. Build and test status

| Check | Status | Evidence |
| --- | --- | --- |
| Main CI | Pass | Latest run `28863223887` succeeded |
| Sandbox workflow | Pass | Latest run `28863223904` succeeded |
| MicroVM workflow | Pass | Latest run `28863223966` succeeded |
| Test suite | Present | 65 test modules, including numbered acceptance tests and OS/console/MCP/installer coverage |
| Local rerun | Not performed | Python and OS-specific dependencies were not installed in the audit clone; current clean-runner workflows are the better signal |
| Lint/format | Not configured | No repository-wide lint or formatting command found |

The README hard-codes a test count. Counts should come from CI because they will otherwise drift as the suite changes.

## 5. Documentation problems

### Root architecture and build documents describe earlier phases

`ARCHITECTURE.md` labels itself version 0.1, omits much of the current package and describes the console and microVM path as future work. `CLAUDE.md` is an original multi-phase build brief and still describes the sandbox primarily as a subprocess contract. `CONSOLE_SPEC.md` and `PROGRESS.md` mix “not built” phases with later completion notes.

Recommended action: write one current architecture from the shipped packages, then move the earlier documents into dated history rather than deleting them.

### Setup instructions contain placeholders

The README uses `git clone <repo>` instead of the actual URL and combines virtual-environment activation into a command that is not reliably cross-platform.

Recommended action: provide the exact repository URL and separate PowerShell and POSIX setup blocks.

### Product name and repository name are not reconciled

The GitHub repository is Tanaka. Package metadata, commands and most documentation say Sentinel Loop or `sentinel-slice`. A reader cannot tell whether Tanaka is the project, a codename or a newer name.

Recommended action: add one sentence near the top: for example, “Tanaka is the repository; Sentinel Loop is the prototype inside it.” If that is not the intended relationship, choose one name before the wider copy pass.

### Voice and claim calibration

The README uses phrases such as “for free,” “the actual product,” “genuine isolation,” repeated references to “your dad” and a narrowly described “59-year-old compliance officer.” These are memorable, but they can feel salesy or patronizing. Broad statements that the current industry answer is merely a vendor promise belong in the thesis, not the operational quickstart.

Use neutral language and scope each security statement to the backend and configuration actually tested. Keep the plain examples; remove the need to prove the whole industry wrong before explaining the tool.

Proposed repository description, for review only:

> An agent-governance experiment where the agent holds no keys, works from a fixed menu and records every action or refusal.

## 6. Organization problems

1. Current architecture and chronological build history share the root.
2. Tests live inside the package while most other project-level concerns are at root; this is workable but should be documented.
3. The public name, package name and command names are not explained consistently.
4. Security claims and thesis language are mixed into the quickstart.
5. Test totals are written into prose rather than shown by CI.
6. There is no lint or formatting policy.

## 7. Security or secret concerns

No private key, provider credential or live secret was found in tracked files.

- `sentinel_slice/keys/cashier_ed25519_public.pem` is a public verification key and intentional package data.
- The private-key marker in `sentinel_slice/console/static/index.html` is a textarea placeholder, not an embedded key.
- `ledger.db` is intentional demo data. It should contain only deterministic, non-personal fixtures.
- TEE attestation is mocked. Current docs must not imply hardware-backed attestation.
- “Genuine isolation” should be limited to the tested platform/backend. A subprocess fallback is not the same boundary as a microVM or OS sandbox.

## 8. Safe cleanup candidates

No tracked source or evidence file is a high-confidence deletion candidate in this pass.

### Candidate: local Python caches and build output

- **Exact paths:** `__pycache__/`, `.pytest_cache/`, `build/`, `dist/` and local virtual-environment folders when present.
- **Contents:** Bytecode, test cache, distributions and installed local environments.
- **Why they are unnecessary:** Python and build tools regenerate them.
- **Evidence:** Ignore rules cover generated Python and build output; no tracked caches/build directories were found.
- **References:** Tooling may use local copies while running; the source does not require committed copies.
- **Risk:** Very low; dependencies or packages may need to be recreated.
- **Recommended action:** Keep ignored and remove locally only for a clean run or disk space. Never commit them.

## 9. Uncertain cleanup candidates

No deletion is approved or performed.

### Candidate: `ARCHITECTURE.md`

- **Contents:** Version 0.1 architecture and proposed swaps.
- **Why it may be unnecessary as a current root document:** It omits current packages and describes implemented console/microVM work as future.
- **Evidence:** Current source contains the console, MCP, multiple containment backends and KVM microVM support.
- **References:** It preserves the original architecture and may explain design decisions.
- **Risk:** Medium.
- **Recommended action:** Write a current `docs/architecture.md`, then move this file to `docs/history/architecture-v0.1.md`. Do not delete.

### Candidate: `CLAUDE.md`

- **Contents:** An original five-phase implementation brief.
- **Why it may be unnecessary as current guidance:** It frames the sandbox around an earlier subprocess design and does not describe the complete current repository.
- **Evidence:** Later containment backends and console code now exist.
- **References:** Likely useful historical implementation rationale; may also guide AI tooling.
- **Risk:** Medium.
- **Recommended action:** Relabel/archive it or replace it with current contributor/agent guidance after reviewing any still-active rules.

### Candidate group: `CONSOLE_SPEC.md` and `PROGRESS.md`

- **Contents:** Console requirements, implementation phases and chronological progress.
- **Why they may be unnecessary at root:** Old “not built” states sit beside later completion notes.
- **Evidence:** The console package and tests now exist.
- **References:** Useful implementation history; no runtime dependency.
- **Risk:** Low to medium.
- **Recommended action:** Extract current console behavior into `docs/console.md` and move the originals to dated history.

### Candidate: `ledger.db`

- **Contents:** A small SQLite demo ledger used for verification.
- **Why it might look unnecessary:** It is generated runtime data and the ignore rules generally exclude databases.
- **Evidence:** The README and ignore exception deliberately keep it as a reproducible acceptance artifact.
- **References:** Verification commands use this exact file.
- **Risk:** High if removed; examples and evidence checks would lose their known input.
- **Recommended action:** Retain unless a replacement fixture and updated validation workflow are approved.

### Candidate: `sentinel_slice/keys/cashier_ed25519_public.pem`

- **Contents:** Public Ed25519 verification key.
- **Why it might look sensitive:** Its PEM format resembles key material.
- **Evidence:** It contains only the public key and is referenced as package/test data.
- **References:** Ledger and signature verification paths use it.
- **Risk:** High if removed without replacing the fixtures.
- **Recommended action:** Retain. Never add the matching private key.

## 10. Files that should be retained

- All `sentinel_slice/` runtime code and tests.
- Three current GitHub Actions workflows.
- `SPEC.md`, `THREATS.md`, `THESIS.md` and `CONTRIBUTING.md`.
- `ledger.db` and the public key as intentional reproducible evidence.
- Policy, capability, kitchen and curriculum fixtures.
- Docker, microVM and installer inputs.
- Historical architecture/build documents after clear labelling.
- License and notice files.

## 11. Recommended target structure

```text
Tanaka/
├── sentinel_slice/
├── microvm/
├── tests/                     # optional future move from package
├── docs/
│   ├── architecture.md
│   ├── console.md
│   ├── security.md
│   ├── operations/
│   ├── thesis/
│   └── history/
├── .github/workflows/
├── Dockerfile
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── NOTICE
```

## 12. Proposed implementation stages

### Stage 1: documentation and naming — low risk

1. Explain Tanaka versus Sentinel Loop once and use the chosen relationship consistently.
2. Correct the clone URL and split platform-specific setup commands.
3. Write a current architecture from the actual packages.
4. Move old architecture, build and progress records into dated history.

### Stage 2: public copy — low risk

1. Move the industry argument into the thesis.
2. Remove patronizing audience examples and absolute security wording.
3. State what each containment backend provides and what remains mocked.
4. Keep the copy simple: fixed menu, short-lived permission, contained action, signed receipt.

### Stage 3: validation contract — low to medium risk

1. Show current test status through CI rather than hard-coded counts.
2. Add a documented lint and formatting policy in a separate change.
3. Keep the demo ledger and public key verification in CI.

### Stage 4: optional organization — medium risk

1. Consider moving package tests to a project-level `tests/` directory only if it improves packaging.
2. Preserve all public commands and fixture paths or provide compatibility redirects.

Human review is required before any deletion, file move, naming change or public-description update.
