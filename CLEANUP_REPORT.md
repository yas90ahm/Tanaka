# Cleanup report

Date: 17 July 2026
Branch: `repo-cleanup`

This pass made the repository easier to enter without throwing away its build
history. No application code changed. Nothing was committed, pushed or merged
as part of this local pass.

## What moved

The current documents now live under `docs/`. Earlier plans and build records
are kept under `docs/history/` so they can still be read without looking like
current instructions.

| Previous path | Current path | Reason |
| --- | --- | --- |
| `ARCHITECTURE.md` | `docs/history/architecture-v0.1.md` | Useful original design, but no longer a complete map of the code |
| `CLAUDE.md` | `docs/history/implementation-brief.md` | Original implementation instructions, not current contributor guidance |
| `CONSOLE_SPEC.md` | `docs/history/CONSOLE_SPEC.md` | Preserves the console plan and its earlier assumptions |
| `PROGRESS.md` | `docs/history/PROGRESS.md` | Preserves the build record and old test totals |
| `SPEC.md` | `docs/SPEC.md` | Still the original slice contract and still useful |
| `THESIS.md` | `docs/THESIS.md` | Long-form design argument, not setup instructions |
| `THREATS.md` | `docs/THREATS.md` | Current security boundary and known limits |

No files were deleted. In particular, `ledger.db` and the committed public key
were retained because the verification example depends on them. The matching
private key is not in the repository.

## Documentation changes

- Rewrote `README.md` as a shorter, calmer entry point. It now explains that
  Tanaka is the repository and Sentinel Loop is the prototype inside it.
- Added `docs/ARCHITECTURE.md` from the current source layout. It follows an
  order through the cashier, signed ticket, selected execution backend, serving
  window and signed receipt ledger.
- Corrected an important claim about tickets. They are signed and
  capability-bound, but the current code does not enforce an expiry.
- Updated `CONTRIBUTING.md` to point to current documents and kept the test,
  append-only, canonical JSON and mock-labelling rules.
- Repaired moved-file references in `CHANGELOG.md`, `docs/SPEC.md`,
  `docs/THESIS.md`, `docs/THREATS.md` and the historical progress record.
- Replaced the package's marketing-style description with a plain description
  in `pyproject.toml`.

## Validation

Completed locally:

- `git diff --check` passed with no whitespace errors.
- A recursive check of local Markdown links returned `MARKDOWN_LINKS_OK`.
- A final stale-path scan found no current links to the old root document
  locations.
- `python -m pytest -q` passed: 271 tests passed and 16 were skipped. The run
  used Python 3.12 with `pytest` and `cryptography` in an isolated validation
  environment.

Not completed locally:

- This pass did not rerun the platform sandbox or microVM jobs.

The repository audit recorded the last checked GitHub Actions runs as passing:
main CI `28863223887`, sandbox `28863223904`, and microVM `28863223966`. Those
runs predate this documentation-only pass; they are useful context, not a new
validation result.

## Human review

These points need a person to decide or confirm:

1. Confirm that the sentence “Tanaka is the repository; Sentinel Loop is the
   prototype inside it” is the naming relationship you want to keep. The Python
   package and commands still use `sentinel-slice` and `sentinel-*`.
2. Decide whether tickets should actually expire. The code records `issued_ts`
   but does not reject an old signed ticket. The documentation now states that
   plainly.
3. Review the containment wording before presenting this as a security product.
   The default subprocess path, operating-system sandboxes and KVM microVM do
   not provide the same guarantee.
4. Keep the mock attestation label visible unless a real hardware attestation
   path is implemented and independently reviewed.
5. Decide whether to publish the unsigned Windows installer. It has no
   auto-update path and Windows may warn about its publisher.
6. Run the sandbox and microVM workflows as well if any later change touches
   execution, packaging or CI.
7. Decide separately whether the repository needs a lint or formatting policy.
   None was added here because that would change the contributor and CI
   contract.

The historical documents should remain in place unless their information has
been deliberately incorporated elsewhere. They are no longer in the way, and
deleting them would gain very little.
