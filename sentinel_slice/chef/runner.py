"""Runner — spawns the standalone chef in an ephemeral workspace, then (on
success only) digests the draft, obtains a MOCK attestation quote, and appends
the single FULFILLED receipt.

EPHEMERALITY (AT08): every code path — success, nonzero chef exit, exception —
destroys the `mkdtemp` workspace in a `finally`. The workspace is the chef's
cwd; the serving window (`serving.window_dir`) is the PERSISTENT content path
and is NOT the workspace.

PRIVACY (AT01): the receipt carries ONLY `result_digest` (sha256 of the draft
bytes) and the `attestation` dict. Draft CONTENT never reaches the ledger.

This module may import stdlib + cryptography + sentinel_slice.{spine,ledger,
attestor,window}. It does NOT import sentinel_slice.kitchen, and it is NOT the
standalone one — the chef (`chef_main.py`) is.
"""

import base64
import hashlib
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass

from sentinel_slice.spine.types import Receipt, Ticket
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.chef.sandbox import SandboxSpec, SubprocessSandbox
from sentinel_slice.window import serving


# Absolute path to the standalone chef; also the SOURCE measured for attestation.
CHEF_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chef_main.py")


@dataclass(frozen=True)
class ChefResult:
    workspace_path: str          # the mkdtemp dir — ALREADY DELETED when returned
    out_dir: str                 # the serving-window dir for this order_id
    draft_path: str              # <out_dir>/output.txt (the order's output artifact)
    draft_bytes: bytes | None    # bytes read back from output.txt on success, else None
    result_digest: str | None    # sha256(draft_bytes).hexdigest() on success, else None
    receipt: Receipt | None      # FULFILLED on success, else REJECTED/EXECUTION_FAILED
    returncode: int              # the chef subprocess exit code
    stderr: str                  # captured chef stderr (for debugging/forged paths)


def run_chef(
    ticket: Ticket,
    *,
    ledger: Ledger,
    public_key_pem_path: str,
    fixtures_root: str,
    attestor,
    window_root: str | None = None,
    order_meta: dict | None = None,
    sandbox=None,
) -> ChefResult:
    """Spawn the chef subprocess on `ticket`, returning a ChefResult.

    On chef exit 0 WITH a readable draft: read the draft bytes back, digest
    them, quote the chef's code measurement via `attestor`, append a FULFILLED
    receipt, and return it. On any execution failure (nonzero exit, OR exit 0
    with no draft): append a REJECTED/EXECUTION_FAILED receipt so the
    cashier-authorized order still leaves an auditable ledger row (SPEC claim 4),
    and surface failure via returncode + receipt. Never raises on a chef
    failure. The ephemeral workspace is destroyed on EVERY path.

    `sandbox` selects the execution backend (default SubprocessSandbox — the
    contract). A ContainerSandbox(runtime="runsc") gives a real isolation
    guarantee on Linux+gVisor behind this same call; see chef/sandbox.py."""
    if sandbox is None:
        sandbox = SubprocessSandbox()
    workspace = tempfile.mkdtemp(prefix="chef_ws_")
    try:
        out_dir = serving.window_dir(ticket.order_id, window_root)
        draft_path = serving.draft_path(ticket.order_id, window_root)

        wire = {
            "ticket_id": ticket.ticket_id,
            "order_id": ticket.order_id,
            "capability_id": ticket.capability_id,
            "scoped_args": ticket.scoped_args,
            "issued_ts": ticket.issued_ts,
            "cashier_sig": base64.b64encode(ticket.cashier_sig).decode("ascii"),
        }
        import json
        payload = json.dumps(wire)

        proc = sandbox.run(SandboxSpec(
            chef_main=CHEF_MAIN,
            pubkey_path=public_key_pem_path,
            fixtures_root=fixtures_root,
            out_dir=out_dir,
            workspace=workspace,
            stdin=payload,
        ))

        # Success requires BOTH a zero exit AND a readable draft. A chef that
        # exits 0 without a draft is handled as an execution failure below (so
        # run_chef never raises and never leaves an accepted order receiptless).
        draft_bytes = None
        if proc.returncode == 0:
            try:
                with open(draft_path, "rb") as f:
                    draft_bytes = f.read()
            except FileNotFoundError:
                draft_bytes = None

        if proc.returncode == 0 and draft_bytes is not None:
            result_digest = hashlib.sha256(draft_bytes).hexdigest()

            with open(CHEF_MAIN, "rb") as f:
                measurement = hashlib.sha256(f.read()).hexdigest()
            attestation = attestor.quote(measurement)

            receipt = ledger.append(
                receipt_id="rcpt-" + uuid.uuid4().hex,
                order_id=ticket.order_id,
                ticket_id=ticket.ticket_id,
                status="FULFILLED",
                reason_code=None,
                result_digest=result_digest,
                attestation=attestation,
                order_meta=order_meta,
            )

            return ChefResult(
                workspace_path=workspace,
                out_dir=out_dir,
                draft_path=draft_path,
                draft_bytes=draft_bytes,
                result_digest=result_digest,
                receipt=receipt,
                returncode=0,
                stderr=proc.stderr,
            )

        # Execution failure (nonzero exit, OR exit 0 with no readable draft):
        # the cashier already authorized and signed this order, so it STILL gets
        # a chained receipt for audit-legibility (SPEC claim 4: every order
        # produces a receipt). EXECUTION_FAILED is beyond SPEC's reason_code
        # enum (documented in PROGRESS.md, like RATE_LIMITED). No content,
        # no digest, no attestation — a failed execution produced no result.
        receipt = ledger.append(
            receipt_id="rcpt-" + uuid.uuid4().hex,
            order_id=ticket.order_id,
            ticket_id=ticket.ticket_id,
            status="REJECTED",
            reason_code="EXECUTION_FAILED",
            result_digest=None,
            attestation=None,
            order_meta=order_meta,
        )
        return ChefResult(
            workspace_path=workspace,
            out_dir=out_dir,
            draft_path=draft_path,
            draft_bytes=None,
            result_digest=None,
            receipt=receipt,
            returncode=proc.returncode,
            stderr=proc.stderr,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
