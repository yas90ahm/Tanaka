"""Policy loading for the cashier.

Loads `sentinel_slice/policies/*.json` VERBATIM into frozen Policy objects
grouped in a PolicySet. The round-trip is the thesis (Phase 5's authoring
form re-emits these exact keys), so this loader performs NO translation,
defaulting, or normalization of values — keys are read exactly as written.

Structural blindness (Phase-3 contract §1): this module imports ONLY stdlib
and `sentinel_slice.spine.*`. It never imports kitchen and never reads,
opens, globs, or stats any fixture mailbox.
"""

import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    role: str
    allowed_capabilities: tuple[str, ...]  # tuple, not list (frozen-hashable)
    rate_limit_per_hour: int


class PolicySet:
    def __init__(self, policies: list[Policy]) -> None:
        self._policies: list[Policy] = list(policies)

    def for_role(self, role: str) -> Policy | None:
        """Return the Policy whose role == role, else None."""
        for policy in self._policies:
            if policy.role == role:
                return policy
        return None


# Absolute path to sentinel_slice/policies, computed from this file's
# location: policy.py lives in sentinel_slice/cashier/, policies is a sibling
# of cashier/ under sentinel_slice/.
POLICIES_DIR: str = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "policies")
)


def load_policy_set(policies_dir: str | None = None) -> PolicySet:
    """Load every *.json file in policies_dir VERBATIM. For each file, read
    obj['policies'] and build one Policy per entry, mapping obj key
    'allowed_capabilities' (list) -> tuple. Default dir = POLICIES_DIR.

    No translation, defaulting, or normalization of values — keys are read
    exactly as written (the round-trip is the thesis). 'rate_limit_per_hour'
    is required: a malformed file missing it raises KeyError (acceptable;
    the committed file is well-formed)."""
    directory = POLICIES_DIR if policies_dir is None else policies_dir
    policies: list[Policy] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        for entry in obj["policies"]:
            policies.append(
                Policy(
                    role=entry["role"],
                    allowed_capabilities=tuple(entry["allowed_capabilities"]),
                    rate_limit_per_hour=entry["rate_limit_per_hour"],
                )
            )
    return PolicySet(policies)
