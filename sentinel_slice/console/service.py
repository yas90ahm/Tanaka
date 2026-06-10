"""ConsoleService — the operator console's business logic, transport-free.

Every console action is a method here: capabilities, policies, simulate,
publish, approve, rollback, activity, receipt, run_drill. Each takes a
RESOLVED `Admin` (the transport resolves the token first) and enforces the
role / separation-of-duties rule itself. No HTTP, no sockets — so the logic is
tested directly and a FastAPI surface later would call these unchanged
(CONSOLE_SPEC non-negotiable #5).

Trust boundaries preserved:
- The console NEVER sees payload content. `activity`/`receipt` read the
  receipt ledger, which carries only digests + order metadata. `simulate`
  runs the PURE `evaluate_order` — no chef, no ledger write, no nonce burned.
- The console WRITES only the policy store (publish/approve/rollback), which
  is itself signed + append-only. The receipt ledger is written by the agent
  loop, never here. The drill writes its OWN scratch ledger.
- Separation of duties is REAL: author vs reviewer, and a reviewer may not
  approve their own proposal. Only the identity SOURCE is mocked (see auth.py).
"""

import os
import shutil
import tempfile
import uuid

from cryptography.hazmat.primitives import serialization

from sentinel_slice import inspector
from sentinel_slice.cashier.engine import evaluate_order
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.console.auth import ROLE_AUTHOR, ROLE_REVIEWER
from sentinel_slice.spine.types import Capability, Order

# Package-relative paths the drill needs (stable, like run_slice computes them).
_SENTINEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FIXTURES_ROOT = os.path.join(_SENTINEL_DIR, "kitchen", "fixtures", "mailbox")
_POISONED = os.path.join(_FIXTURES_ROOT, "user.kenji", "poisoned.txt")


# ---- typed errors; the transport maps these to HTTP status codes ----
class ConsoleError(Exception):
    http_status = 400


class BadRequestError(ConsoleError):
    http_status = 400


class AuthError(ConsoleError):
    http_status = 403


class NotFoundError(ConsoleError):
    http_status = 404


class ConflictError(ConsoleError):
    http_status = 409


class ConsoleService:
    def __init__(
        self,
        *,
        private_key,
        public_key_pem_path: str,
        ledger_db_path: str,
        policy_store,
        policies_dir: str,
        catalog: dict[str, Capability],
        custom_dir: str | None = None,
    ) -> None:
        self._private_key = private_key
        self._public_key_pem_path = public_key_pem_path
        with open(public_key_pem_path, "rb") as fh:
            self._public_key = serialization.load_pem_public_key(fh.read())
        self._ledger_db_path = ledger_db_path
        self._policy_store = policy_store
        self._policies_dir = policies_dir
        self._catalog = catalog
        # When set, the menu is live-loaded from disk (built-in + this operator
        # custom dir) so menu curation is reflected immediately; menu-curation
        # endpoints require it.
        self._custom_dir = custom_dir

    def _live_catalog(self, *, include_disabled: bool = False) -> dict:
        """The current catalog. If a custom dir is configured, reload from disk
        (so operator-created capabilities appear without a restart); else the
        static catalog passed at construction."""
        if self._custom_dir is None:
            return self._catalog
        from sentinel_slice.menu.catalog import load_catalog

        return load_catalog(custom_dir=self._custom_dir,
                            include_disabled=include_disabled)

    # ---------- auth helpers ----------
    @staticmethod
    def _require_role(admin, role) -> None:
        if admin is None:
            raise AuthError("no admin identity")
        if admin.role != role:
            raise AuthError(
                "role {!r} required; {!r} has role {!r}".format(
                    role, admin.id, admin.role
                )
            )

    @staticmethod
    def _require_any_role(admin) -> None:
        if admin is None:
            raise AuthError("no admin identity")

    # ---------- validation ----------
    def _validate_policy_list(self, policies) -> None:
        if not isinstance(policies, list) or not policies:
            raise BadRequestError("candidate_policy must be a non-empty list")
        for p in policies:
            if not isinstance(p, dict):
                raise BadRequestError("each policy must be an object")
            for k in ("role", "allowed_capabilities", "rate_limit_per_hour"):
                if k not in p:
                    raise BadRequestError("policy missing required key: " + k)
            if not isinstance(p["role"], str):
                raise BadRequestError("policy.role must be a string")
            if not isinstance(p["allowed_capabilities"], list):
                raise BadRequestError("policy.allowed_capabilities must be a list")
            if not isinstance(p["rate_limit_per_hour"], int) or isinstance(
                p["rate_limit_per_hour"], bool
            ):
                raise BadRequestError("policy.rate_limit_per_hour must be an int")
            paused = p.get("paused_capabilities", [])
            if not isinstance(paused, list):
                raise BadRequestError("policy.paused_capabilities must be a list")

    def _candidate_policy_set(self, policies) -> PolicySet:
        return PolicySet(
            [
                Policy(
                    role=p["role"],
                    allowed_capabilities=tuple(p["allowed_capabilities"]),
                    rate_limit_per_hour=p["rate_limit_per_hour"],
                    paused_capabilities=tuple(p.get("paused_capabilities", ())),
                )
                for p in policies
            ]
        )

    def _needs_second_admin(self, policies) -> list[str]:
        """Capability ids in the candidate that the catalog marks
        requires_second_admin — the gate for the pending/approval workflow."""
        flagged = set()
        cat = self._live_catalog()
        for p in policies:
            for cap_id in p.get("allowed_capabilities", []):
                cap = cat.get(cap_id)
                if cap is not None and cap.requires_second_admin:
                    flagged.add(cap_id)
        return sorted(flagged)

    def _materialize(self) -> None:
        self._policy_store.materialize_active(
            os.path.join(self._policies_dir, "active.json")
        )

    def _find_version(self, seq) -> dict:
        for row in self._policy_store.read_all():
            if row["seq"] == seq:
                return row
        raise NotFoundError("no policy version with seq {}".format(seq))

    # ---------- read endpoints ----------
    def capabilities(self, admin) -> dict:
        self._require_any_role(admin)
        items = []
        for cap in self._live_catalog().values():
            items.append(
                {
                    "id": cap.id,
                    "name": cap.name,
                    "description": cap.description,
                    "inputs": cap.inputs,
                    "outputs": cap.outputs,
                    "side_effects": cap.side_effects,
                    "scope": cap.scope,
                    "risk_class": cap.risk_class,
                    "recommended_max_rate": cap.recommended_max_rate,
                    "requires_second_admin": cap.requires_second_admin,
                }
            )
        items.sort(key=lambda c: c["id"])
        return {"capabilities": items}

    def policies(self, admin) -> dict:
        self._require_any_role(admin)
        history = []
        for row in self._policy_store.read_all():
            history.append(
                {
                    "seq": row["seq"],
                    "version_id": row["version_id"],
                    "author": row["author"],
                    "reason": row["reason"],
                    "status": row["status"],
                    "approved_by": row["approved_by"],
                }
            )
        active = self._policy_store.active_version()
        return {
            "active": None
            if active is None
            else {
                "seq": active["seq"],
                "version_id": active["version_id"],
                "policies": active["policies"],
            },
            "history": history,
        }

    def activity(self, admin) -> dict:
        self._require_any_role(admin)
        rows = self._read_ledger_rows()
        return inspector.build_report(rows, self._public_key)

    def receipt(self, admin, seq) -> dict:
        self._require_any_role(admin)
        for s, row in self._read_ledger_rows():
            if s == seq:
                # Already only public fields (digest + metadata + chain + sig).
                return {"seq": s, "receipt": row}
        raise NotFoundError("no receipt with seq {}".format(seq))

    def _read_ledger_rows(self):
        """Read the live receipt ledger; tolerate an absent/empty ledger so
        the Activity screen shows zero rather than erroring."""
        import sqlite3

        try:
            return inspector.read_rows(self._ledger_db_path)
        except (sqlite3.OperationalError, ValueError):
            return []

    # ---------- simulate (pure, no writes) ----------
    def simulate(self, admin, candidate_policy, sample_orders) -> dict:
        self._require_role(admin, ROLE_AUTHOR)
        self._validate_policy_list(candidate_policy)
        if not isinstance(sample_orders, list) or not sample_orders:
            raise BadRequestError("sample_orders must be a non-empty list")

        pset = self._candidate_policy_set(candidate_policy)
        store = CashierStore()  # throwaway — Simulate consumes no real state
        results = []
        for s in sample_orders:
            if not isinstance(s, dict):
                raise BadRequestError("each sample order must be an object")
            for k in ("principal", "role", "capability_id"):
                if k not in s:
                    raise BadRequestError("sample order missing key: " + k)
            order = Order(
                order_id="sim-" + uuid.uuid4().hex,
                principal=s["principal"],
                role=s["role"],
                capability_id=s["capability_id"],
                args=s.get("args", {}),
                nonce="sim-" + uuid.uuid4().hex,
                ts="simulation",
            )
            decision = evaluate_order(
                order, menu=self._live_catalog(), policy_set=pset, store=store
            )
            results.append(
                {
                    "principal": s["principal"],
                    "role": s["role"],
                    "capability_id": s["capability_id"],
                    "allowed": decision.accepted,
                    "reason_code": decision.reason_code,
                }
            )
        return {"results": results}

    # ---------- write endpoints (policy store only) ----------
    def _publish_content(self, *, policies, author, reason) -> dict:
        """Shared by publish + rollback: apply the second-admin gate, append a
        signed version (active or pending), materialize if active."""
        flagged = self._needs_second_admin(policies)
        status = "pending" if flagged else "active"
        row = self._policy_store.append_version(
            policies=policies, author=author, reason=reason, status=status
        )
        if status == "active":
            self._materialize()
        return {
            "seq": row["seq"],
            "version_id": row["version_id"],
            "status": status,
            "requires_second_admin_for": flagged,
        }

    def publish(self, admin, candidate_policy, reason) -> dict:
        self._require_role(admin, ROLE_AUTHOR)
        self._validate_policy_list(candidate_policy)
        if not isinstance(reason, str) or not reason.strip():
            raise BadRequestError("a non-empty change reason is required")
        return self._publish_content(
            policies=candidate_policy, author=admin.id, reason=reason
        )

    def approve(self, admin, seq) -> dict:
        self._require_role(admin, ROLE_REVIEWER)
        target = self._find_version(seq)
        if target["status"] != "pending":
            raise ConflictError(
                "version seq {} is {!r}, not pending".format(seq, target["status"])
            )
        if target["author"] == admin.id:
            raise AuthError(
                "separation of duties: {!r} cannot approve their own "
                "proposal (seq {})".format(admin.id, seq)
            )
        row = self._policy_store.append_version(
            policies=target["policies"],
            author=target["author"],
            reason="approved proposal seq {} (reviewer {})".format(seq, admin.id),
            status="active",
            approved_by=admin.id,
        )
        self._materialize()
        return {
            "seq": row["seq"],
            "version_id": row["version_id"],
            "status": "active",
            "approved_by": admin.id,
            "approved_proposal_seq": seq,
        }

    def rollback(self, admin, target_seq, reason) -> dict:
        self._require_role(admin, ROLE_AUTHOR)
        if not isinstance(reason, str) or not reason.strip():
            raise BadRequestError("a non-empty rollback reason is required")
        target = self._find_version(target_seq)
        # Rollback re-publishes the target's content through the SAME gate, so
        # rolling forward INTO a second-admin policy still needs approval.
        return self._publish_content(
            policies=target["policies"],
            author=admin.id,
            reason="rollback to seq {}: {}".format(target_seq, reason),
        )

    # ---------- drill (own scratch ledger) ----------
    def run_drill(self, admin) -> dict:
        self._require_any_role(admin)

        # Lazy imports: heavy and only needed here.
        from sentinel_slice.attestor.mock import MockAttestor
        from sentinel_slice.cashier.policy import load_policy_set
        from sentinel_slice.curriculum.drill import run_drill as _run_drill
        from sentinel_slice.ledger.receipts import Ledger
        from sentinel_slice.loop import SentinelLoop

        active = self._policy_store.active_version()
        if active is not None:
            pset = self._candidate_policy_set(active["policies"])
        else:
            pset = load_policy_set()  # fall back to on-disk default

        tmp = tempfile.mkdtemp(prefix="console_drill_")
        try:
            ledger = Ledger(os.path.join(tmp, "drill.db"), self._private_key)
            loop = SentinelLoop(
                private_key=self._private_key,
                ledger=ledger,
                menu=self._live_catalog(),
                policy_set=pset,
                store=CashierStore(),
                public_key_pem_path=self._public_key_pem_path,
                fixtures_root=_FIXTURES_ROOT,
                attestor=MockAttestor(),
                window_root=os.path.join(tmp, "win"),
            )
            return _run_drill(loop, _POISONED)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ---------- menu curation (no-code) ----------
    def _require_menu_curation(self):
        if self._custom_dir is None:
            raise ConflictError("menu curation is not configured (no custom dir)")

    def _builtin_ids(self) -> set:
        from sentinel_slice.menu.catalog import CAPABILITIES_DIR, load_catalog

        return set(load_catalog(CAPABILITIES_DIR, include_disabled=True))

    def templates(self, admin) -> dict:
        """The building blocks an operator composes menu items from."""
        self._require_any_role(admin)
        from sentinel_slice.menu.templates import TEMPLATES

        out = []
        for behavior, t in sorted(TEMPLATES.items()):
            out.append({
                "behavior": behavior,
                "label": t["label"],
                "summary": t["summary"],
                "default_risk": t["default_risk"],
                "side_effects": t["side_effects"],
                "default_requires_user_confirmation":
                    t["default_requires_user_confirmation"],
                "default_requires_second_admin": t["default_requires_second_admin"],
                "default_recommended_max_rate": t["default_recommended_max_rate"],
            })
        return {"templates": out}

    def menu(self, admin) -> dict:
        """The whole menu for the curation screen: every capability incl.
        disabled ones, flagged built-in (locked) vs operator-created (editable)."""
        self._require_any_role(admin)
        from sentinel_slice.menu.catalog import load_catalog

        if self._custom_dir is None:
            cat = self._catalog
        else:
            cat = load_catalog(custom_dir=self._custom_dir, include_disabled=True)
        builtin = self._builtin_ids()
        items = []
        for cap in sorted(cat.values(), key=lambda c: c.id):
            items.append({
                "id": cap.id,
                "name": cap.name,
                "behavior": cap.resolved_behavior(),
                "risk_class": cap.risk_class,
                "side_effects": cap.side_effects,
                "enabled": cap.enabled,
                "requires_user_confirmation": cap.requires_user_confirmation,
                "requires_second_admin": cap.requires_second_admin,
                "editable": cap.id not in builtin,   # built-ins are locked
            })
        return {"capabilities": items}

    def create_capability(self, admin, form) -> dict:
        """Compose a new menu item from a template + form fields. No code, no
        JSON. Author only."""
        self._require_role(admin, ROLE_AUTHOR)
        self._require_menu_curation()
        from sentinel_slice.menu.builder import CapabilityBuildError, build_descriptor
        from sentinel_slice.menu.catalog import save_custom_capability

        if not isinstance(form, dict):
            raise BadRequestError("expected a capability form object")
        try:
            descriptor = build_descriptor(
                behavior=form.get("behavior"),
                capability_id=form.get("capability_id"),
                name=form.get("name", ""),
                description=form.get("description", ""),
                risk_class=form.get("risk_class"),
                recommended_max_rate=form.get("recommended_max_rate"),
                requires_user_confirmation=form.get("requires_user_confirmation"),
                requires_second_admin=form.get("requires_second_admin"),
                enabled=form.get("enabled", True),
            )
        except CapabilityBuildError as exc:
            raise BadRequestError(str(exc))
        try:
            save_custom_capability(descriptor, self._custom_dir)
        except ValueError as exc:
            raise ConflictError(str(exc))
        return {"created": descriptor["id"], "behavior": descriptor["behavior"],
                "enabled": descriptor["enabled"]}

    def set_capability_enabled(self, admin, capability_id, enabled) -> dict:
        self._require_role(admin, ROLE_AUTHOR)
        self._require_menu_curation()
        from sentinel_slice.menu.catalog import set_custom_capability_enabled

        if capability_id in self._builtin_ids():
            raise ConflictError("built-in capabilities can't be toggled here")
        try:
            set_custom_capability_enabled(
                capability_id, bool(enabled), self._custom_dir)
        except ValueError as exc:
            raise NotFoundError(str(exc))
        return {"id": capability_id, "enabled": bool(enabled)}

    def delete_capability(self, admin, capability_id) -> dict:
        self._require_role(admin, ROLE_AUTHOR)
        self._require_menu_curation()
        from sentinel_slice.menu.catalog import delete_custom_capability

        if capability_id in self._builtin_ids():
            raise ConflictError("built-in capabilities can't be deleted")
        try:
            delete_custom_capability(capability_id, self._custom_dir)
        except ValueError as exc:
            raise NotFoundError(str(exc))
        return {"deleted": capability_id}
