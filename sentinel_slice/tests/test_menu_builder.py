# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""No-code menu building (v0.7) — an operator composes a new menu item from a
template, with no JSON and no code, and it actually runs.

Pins: the builder fills technical fields from the template and validates the
form; persistence + enable/disable + delete; disabled items are off the live
menu; built-in ids can't be shadowed; and the headline — a capability created
purely from a form executes through the real cashier -> signed-behavior ->
chef -> receipt path and produces the behavior's output.
"""

import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu import catalog as catalog_mod
from sentinel_slice.menu.builder import CapabilityBuildError, build_descriptor
from sentinel_slice.menu.catalog import (
    delete_custom_capability,
    load_catalog,
    save_custom_capability,
    set_custom_capability_enabled,
)
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"


def test_builder_fills_template_fields_and_defaults():
    d = build_descriptor(
        behavior="docs_summarize",
        capability_id="cap.contracts.summarize.v1",
        name="Summarize contracts",
        description="Summaries of contracts in my queue",
    )
    # Technical fields come from the template; the operator never typed them.
    assert d["behavior"] == "docs_summarize"
    assert d["scoped_input"] == "doc_id"
    assert d["inputs"] == {"doc_id": "string"}
    assert d["side_effects"] == "none"
    assert d["risk_class"] == "low"          # template default
    assert d["recommended_max_rate"] == 30
    assert d["enabled"] is True


def test_builder_validation():
    with pytest.raises(CapabilityBuildError):
        build_descriptor(behavior="nope", capability_id="cap.x.v1", name="X")
    with pytest.raises(CapabilityBuildError):
        build_descriptor(behavior="docs_summarize", capability_id="Bad Id!", name="X")
    with pytest.raises(CapabilityBuildError):
        build_descriptor(behavior="docs_summarize", capability_id="cap.x.v1", name="")


def test_persist_enable_disable_delete(tmp_path):
    custom = str(tmp_path / "custom")
    d = build_descriptor(behavior="docs_summarize",
                         capability_id="cap.contracts.summarize.v1",
                         name="Summarize contracts")
    save_custom_capability(d, custom)

    # On the live menu by default.
    assert "cap.contracts.summarize.v1" in load_catalog(custom_dir=custom)

    # Disable -> off the live menu, still visible to the curation view.
    set_custom_capability_enabled("cap.contracts.summarize.v1", False, custom)
    assert "cap.contracts.summarize.v1" not in load_catalog(custom_dir=custom)
    assert "cap.contracts.summarize.v1" in load_catalog(
        custom_dir=custom, include_disabled=True)

    # Re-enable, then delete.
    set_custom_capability_enabled("cap.contracts.summarize.v1", True, custom)
    assert "cap.contracts.summarize.v1" in load_catalog(custom_dir=custom)
    delete_custom_capability("cap.contracts.summarize.v1", custom)
    assert "cap.contracts.summarize.v1" not in load_catalog(
        custom_dir=custom, include_disabled=True)


def test_cannot_shadow_builtin(tmp_path):
    d = build_descriptor(behavior="draft_reply",
                         capability_id="cap.email.draft_reply.v1", name="Dup")
    with pytest.raises(ValueError):
        save_custom_capability(d, str(tmp_path / "custom"))


def test_operator_created_capability_actually_runs(tmp_path):
    """The headline: a menu item made from a FORM (no code) executes."""
    custom = str(tmp_path / "custom")
    descriptor = build_descriptor(
        behavior="docs_summarize",
        capability_id="cap.contracts.summarize.v1",
        name="Summarize contracts",
        description="Summaries for the review queue",
    )
    save_custom_capability(descriptor, custom)

    menu = load_catalog(custom_dir=custom)
    assert "cap.contracts.summarize.v1" in menu

    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    policy = PolicySet([Policy(role="account_manager",
                              allowed_capabilities=("cap.contracts.summarize.v1",),
                              rate_limit_per_hour=10)])
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=menu, policy_set=policy, store=CashierStore(),
        public_key_pem_path=str(pub), fixtures_root=str(MAILBOX),
        attestor=MockAttestor(), window_root=str(tmp_path / "win"))

    outcome = loop.place(Order(
        order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
        role="account_manager", capability_id="cap.contracts.summarize.v1",
        args={"doc_id": "user.kenji/report"}, nonce="n-" + uuid.uuid4().hex,
        ts="2026-06-10T00:00:00+00:00"))

    assert outcome.accepted is True
    chef = loop.last_chef
    assert chef.receipt.status == "FULFILLED"
    # It ran the docs_summarize behavior the template named.
    assert chef.draft_bytes.decode("utf-8").startswith("Summary of user.kenji/report")
