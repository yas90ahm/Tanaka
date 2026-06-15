# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Template behaviors (v0.8) — a non-technical person authors a BEHAVIOR as
data (a message template), no code.

Pins: the builder requires a template for the template behavior and stores it
as signed config; a capability whose behavior is a template, created from a
form, executes end to end and renders the template with the safe fields; and
the renderer is SAFE — only $name substitution, no attribute access / code.
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
from sentinel_slice.menu.builder import CapabilityBuildError, build_descriptor
from sentinel_slice.menu.catalog import load_catalog, save_custom_capability
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"


def test_builder_requires_template_for_template_behavior():
    with pytest.raises(CapabilityBuildError):
        build_descriptor(behavior="template",
                         capability_id="cap.ack.v1", name="Acknowledge")
    d = build_descriptor(behavior="template", capability_id="cap.ack.v1",
                         name="Acknowledge",
                         template="Re: $subject\n\nNoted. ($word_count words)\n")
    assert d["behavior"] == "template"
    assert d["behavior_config"] == {
        "template": "Re: $subject\n\nNoted. ($word_count words)\n"}


def test_non_template_behavior_has_empty_config():
    d = build_descriptor(behavior="docs_summarize",
                         capability_id="cap.x.v1", name="X")
    assert d["behavior_config"] == {}


def test_operator_authored_template_behavior_runs(tmp_path):
    """The headline: a non-technical operator writes a message template (data,
    not code) and it executes through the real pipeline."""
    custom = str(tmp_path / "custom")
    descriptor = build_descriptor(
        behavior="template",
        capability_id="cap.ack.v1",
        name="Acknowledge receipt",
        template="Re: $subject\n\nThanks $first_line — received "
                 "($word_count words). No action taken.\n",
    )
    save_custom_capability(descriptor, custom)

    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    policy = PolicySet([Policy(role="account_manager",
                              allowed_capabilities=("cap.ack.v1",),
                              rate_limit_per_hour=10)])
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(custom_dir=custom), policy_set=policy,
        store=CashierStore(), public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX), attestor=MockAttestor(),
        window_root=str(tmp_path / "win"))

    outcome = loop.place(Order(
        order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
        role="account_manager", capability_id="cap.ack.v1",
        args={"doc_id": "user.kenji/t-001"}, nonce="n-" + uuid.uuid4().hex,
        ts="2026-06-10T00:00:00+00:00"))

    assert outcome.accepted is True
    out = loop.last_chef.draft_bytes.decode("utf-8")
    # $subject was pulled from the fixture; $word_count computed; template text
    # rendered. (t-001 has Subject: Acme Corp Q3 onboarding.)
    assert out.startswith("Re: Acme Corp Q3 onboarding")
    assert "received (" in out and "words). No action taken." in out


def test_template_renderer_is_safe_against_attribute_access(tmp_path):
    """A template that tries attribute access / code is left literal — the
    renderer only does simple $name substitution (string.Template)."""
    custom = str(tmp_path / "custom")
    descriptor = build_descriptor(
        behavior="template", capability_id="cap.evil.v1", name="Evil",
        # Not a valid $identifier -> string.Template leaves it untouched.
        template="hack=${resource.__class__} end\n")
    save_custom_capability(descriptor, custom)

    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(custom_dir=custom),
        policy_set=PolicySet([Policy(role="account_manager",
                                     allowed_capabilities=("cap.evil.v1",),
                                     rate_limit_per_hour=10)]),
        store=CashierStore(), public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX), attestor=MockAttestor(),
        window_root=str(tmp_path / "win"))

    outcome = loop.place(Order(
        order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
        role="account_manager", capability_id="cap.evil.v1",
        args={"doc_id": "user.kenji/t-001"}, nonce="n-" + uuid.uuid4().hex,
        ts="2026-06-10T00:00:00+00:00"))

    out = loop.last_chef.draft_bytes.decode("utf-8")
    # No attribute access happened; the literal text survived, no class repr.
    assert "__class__" in out          # left as literal text
    assert "<class" not in out         # nothing was evaluated
