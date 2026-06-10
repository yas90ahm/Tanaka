"""Console identity — a MOCK identity provider.

==============================  MOCK IDENTITY  ==============================
!!! THIS IS NOT REAL AUTHENTICATION. !!!

`AdminRegistry` maps a static shared token string to an admin identity. There
is no password, no session, no SSO, no expiry, no revocation. It exists so the
console can enforce SEPARATION OF DUTIES (author vs reviewer, and "you cannot
approve your own change") in the slice — that enforcement is REAL. Only the
IDENTITY SOURCE is mocked. A real deployment swaps the token lookup for
SSO/OIDC behind the same `resolve()` seam; nothing else changes.

Flag this as loudly as the MockAttestor. See CONSOLE_SPEC "Identity & auth".
============================================================================
"""

import json
from dataclasses import dataclass

# The two console roles. Separation of duties is built on this distinction.
ROLE_AUTHOR = "author"      # may simulate / publish / rollback policy
ROLE_REVIEWER = "reviewer"  # may approve a pending (second-admin) change
ROLES = (ROLE_AUTHOR, ROLE_REVIEWER)


@dataclass(frozen=True)
class Admin:
    """A resolved console operator. `id` is the human identity used for the
    audit trail (who published / who approved); `role` gates what they can do."""
    id: str
    role: str


class AdminRegistry:
    """MOCK token -> Admin lookup. Real deployments replace this seam."""

    def __init__(self, token_to_admin: dict[str, Admin]) -> None:
        self._by_token = dict(token_to_admin)

    def resolve(self, token: str | None) -> Admin | None:
        """Return the Admin for `token`, or None if the token is unknown /
        missing. None means 401 at the transport layer."""
        if not token:
            return None
        return self._by_token.get(token)


def default_dev_registry() -> AdminRegistry:
    """A MOCK two-admin registry for local development and tests: one author,
    one reviewer, with obvious dev tokens. NEVER use these tokens anywhere
    real — they are public, in source, and unexpiring."""
    return AdminRegistry(
        {
            "dev-author-token": Admin(id="tanaka", role=ROLE_AUTHOR),
            "dev-reviewer-token": Admin(id="reviewer-rao", role=ROLE_REVIEWER),
        }
    )


def load_registry(config_path: str) -> AdminRegistry:
    """Load a MOCK registry from a JSON file:
        {"tokens": {"<token>": {"id": "...", "role": "author|reviewer"}, ...}}
    Still a mock — a static token table, just not hard-coded."""
    with open(config_path, "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    table = {}
    for token, who in obj["tokens"].items():
        if who["role"] not in ROLES:
            raise ValueError("admin {!r} has invalid role {!r}".format(
                who.get("id"), who["role"]))
        table[token] = Admin(id=who["id"], role=who["role"])
    return AdminRegistry(table)
