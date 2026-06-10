"""Authoring form for the account_manager policy (Phase 5, Worker A).

This module is the GENERATOR of `sentinel_slice/policies/account_manager.json`.
The committed policy file is, by construction, byte-identical to
`emit_policy_bytes(DEFAULT_ROLE, [DEFAULT_CAPABILITY], DEFAULT_RATE)` so the
authoring round-trip (AT09) is exact: the form's output and the engine's input
are the same bytes.

`emit_policy_bytes` is PURE (no I/O, no prompts, deterministic). `main()` is the
one-screen CLI form; importing this module never prompts or writes — prompting
and the file write happen only when `main()` is invoked.
"""

import json
import os
import sys

DEFAULT_ROLE = "account_manager"
DEFAULT_CAPABILITY = "cap.email.draft_reply.v1"
DEFAULT_RATE = 5

# policy_form.py lives in sentinel_slice/authoring/. Go up one to
# sentinel_slice/, then policies/account_manager.json.
POLICY_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.pardir,
        "policies",
        "account_manager.json",
    )
)


def emit_policy_bytes(
    role: str,
    allowed_capabilities: list[str],
    rate_limit_per_hour: int,
) -> bytes:
    """Return the exact policy-file bytes for the given inputs.

    Serialization is FROZEN: json.dumps(obj, indent=2) plus exactly one
    trailing newline, encoded UTF-8. Key insertion order is role,
    allowed_capabilities, rate_limit_per_hour. No sort_keys. Pure/deterministic.
    """
    obj = {
        "policies": [
            {
                "role": role,
                "allowed_capabilities": list(allowed_capabilities),
                "rate_limit_per_hour": rate_limit_per_hour,
            }
        ]
    }
    return (json.dumps(obj, indent=2) + "\n").encode("utf-8")


def _prompt(label: str, default: str) -> str:
    """Prompt with a shown default; empty input returns the default."""
    raw = input(f"{label} [{default}]: ").strip()
    return raw if raw else default


def main() -> int:
    """One-screen CLI form: prompt role, capability, rate; write POLICY_PATH."""
    role = _prompt("role", DEFAULT_ROLE)
    capability = _prompt("capability id", DEFAULT_CAPABILITY)

    rate_raw = _prompt("rate limit per hour", str(DEFAULT_RATE))
    try:
        rate = int(rate_raw)
    except ValueError:
        print(f"invalid rate {rate_raw!r}; using default {DEFAULT_RATE}")
        rate = DEFAULT_RATE

    data = emit_policy_bytes(role, [capability], rate)

    # Binary write so the trailing-newline bytes are exact (no platform
    # newline translation).
    with open(POLICY_PATH, "wb") as fh:
        fh.write(data)

    print(f"wrote {POLICY_PATH} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
