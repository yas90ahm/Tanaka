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
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass

from sentinel_slice.spine.types import Receipt, Ticket
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.window import serving


# Absolute path to the standalone chef; also the SOURCE measured for attestation.
CHEF_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chef_main.py")


@dataclass(frozen=True)
class ChefResult:
    workspace_path: str          # the mkdtemp dir — ALREADY DELETED when returned
    out_dir: str                 # the serving-window dir for this order_id
    draft_path: str              # <out_dir>/draft.txt
    draft_bytes: bytes | None    # bytes read back from draft.txt on success, else None
    result_digest: str | None    # sha256(draft_bytes).hexdigest() on success, else None
    receipt: Receipt | None      # the FULFILLED receipt appended, else None
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
) -> ChefResult:
    """Spawn the chef subprocess on `ticket`, returning a ChefResult.

    On chef exit 0: read the draft bytes back, digest them, quote the chef's
    code measurement via `attestor`, append a FULFILLED receipt, and return it.
    On any nonzero exit: append NOTHING; surface failure via receipt=None +
    returncode (does NOT raise). The ephemeral workspace is destroyed on EVERY
    path."""
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

        proc = subprocess.run(
            [sys.executable, CHEF_MAIN, public_key_pem_path, fixtures_root, out_dir],
            input=payload,
            capture_output=True,
            text=True,
            cwd=workspace,
        )

        if proc.returncode == 0:
            with open(draft_path, "rb") as f:
                draft_bytes = f.read()
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

        # Nonzero exit: append no receipt, do not raise.
        return ChefResult(
            workspace_path=workspace,
            out_dir=out_dir,
            draft_path=draft_path,
            draft_bytes=None,
            result_digest=None,
            receipt=None,
            returncode=proc.returncode,
            stderr=proc.stderr,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
