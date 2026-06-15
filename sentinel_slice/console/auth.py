"""Console identity types — the resolved operator and the two roles.

The IDENTITY SOURCE is now real Ed25519 request authentication (see
`signed_auth.py`): an admin proves possession of a private key on every
request, verified against a registry of public keys. There is no shared-secret
token table anymore.

Separation of duties is built on the two roles below and enforced in
service.py on the resolved `Admin` (author vs reviewer; "cannot approve your
own change"). That enforcement is unchanged; only the way an `Admin` is
authenticated became real.
"""

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
