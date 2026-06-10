"""End-to-end entrypoint: one honest order and one injected (probe) order into
a SINGLE ledger, then the standalone verifier over the resulting chain.

The HUMAN runs this once to produce the committed `ledger.db`. Workers do NOT
execute it. Output is three lines: the honest summary, the injected summary,
and the verifier's stdout (`OK verified=2`).
"""

import os
import subprocess
import sys

from sentinel_slice.loop import build_default
from sentinel_slice.diner.agent import run_honest, run_injected


def main() -> int:
    loop = build_default("ledger.db")

    poisoned_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "kitchen",
        "fixtures",
        "mailbox",
        "user.kenji",
        "poisoned.txt",
    )

    # --- Honest order (on-menu, fulfilled by the chef) ---
    # Read the outcome from the chef result, NOT read_receipts()[-1]: on a chef
    # failure the last row is an EXECUTION_FAILED receipt (not the FULFILLED
    # one), and acceptance never implies a draft exists.
    h = run_honest(loop)
    chef = loop.last_chef
    receipt = chef.receipt if chef is not None else None
    status = receipt.status if receipt is not None else "NONE"
    digest = receipt.result_digest if receipt is not None else None
    print(
        f"honest: accepted={h['accepted']} fulfilled={h['fulfilled']} "
        f"status={status} digest={digest}"
    )

    # --- Injected order (off-menu probe, rejected) into the SAME ledger ---
    i = run_injected(loop, poisoned_path)
    print(f"injected: accepted={i['accepted']} reason={i['reason_code']}")

    # --- Verify the resulting chain via the standalone verifier ---
    verifier = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "verify_ledger.py"
    )
    pubkey = loop.public_key_pem_path
    proc = subprocess.run(
        [sys.executable, verifier, "ledger.db", pubkey],
        capture_output=True,
        text=True,
    )
    print(proc.stdout.strip())

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
