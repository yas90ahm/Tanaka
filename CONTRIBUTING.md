# Contributing to Sentinel Loop

Thanks for looking. This repo is a vertical slice with a deliberately high bar
for what counts as "done." Please read these before opening a PR — they are the
same non-negotiables the codebase was built under (`CLAUDE.md`), and they are
what keep the project trustworthy.

## The non-negotiables

1. **Every test asserts a behavior or value** — exact dict equality, full
   receipt contents, process-spawn counts, exit codes. No shape-only or
   substring-only assertions. A test that would still pass against a stub is
   not a test.
2. **Nothing mocked is allowed to look real.** If you add a stand-in, it must
   announce itself (`"mock": true`, a loud docstring, a `PROGRESS.md` entry).
   If a component would quietly need a capability the design forbids (network
   in the chef, kitchen imports in the cashier, content in the ledger), STOP
   and flag it rather than working around it.
3. **The ledger and the policy store are append-only by construction.** No
   `UPDATE`/`DELETE` in their modules — there are grep tests that enforce this.
4. **Canonical JSON for all hashing/signing:** `sort_keys=True,
   separators=(",", ":")`, UTF-8 bytes, via the one `spine.canonical` helper.
5. **No LLM anywhere in the slice.** The diner is deterministic; the thesis
   under test is the governance path, not a model.
6. **Standalone verifiers stay standalone.** `verify_ledger.py` and
   `verify_policy_history.py` import nothing from `sentinel_slice`.
7. Python 3.11+; runtime deps limited to `cryptography`.

## Running the checks locally

```sh
pip install -e ".[dev]"
python -m pytest
python sentinel_slice/verify_ledger.py ledger.db sentinel_slice/keys/cashier_ed25519_public.pem
```

CI runs the same on every push and pull request.

## Where to read first

`SPEC.md` and `ARCHITECTURE.md` (the original slice), then `CONSOLE_SPEC.md`
(the operator console), then `PROGRESS.md` (what's BUILT / PARTIAL / STUB and
what's mocked). The agent-infrastructure essays are the thesis the code serves.

## Developer Certificate of Origin + future licensing

The project is Apache-2.0. By submitting a contribution you certify you wrote
it (or have the right to submit it) and license it under Apache-2.0 — please
sign off your commits (`git commit -s`, the standard DCO).

Note: the maintainer may in future offer the project (or an open-core build of
it) under additional commercial terms. To keep that option open, substantial
contributions may be asked to agree to a lightweight Contributor License
Agreement. If/when that applies it will be requested explicitly on the PR; for
now a DCO sign-off is all that's needed.
