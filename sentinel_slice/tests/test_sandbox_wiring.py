# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Sandbox wiring (v0.12) — the containment backend flows end to end.

Pins the plumbing (no real AppContainer needed — a fake backend stands in):
the SentinelLoop carries a sandbox and run_chef uses it (the receipt's
containment proves which ran); build_default threads it; the consumer path
uses it too; the app-home sandbox marker round-trips and steers
_resolve_sandbox's 'auto'; and an explicit/auto appcontainer choice degrades
to None (subprocess) when AppContainer is unavailable.
"""

import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice import apphome
from sentinel_slice.apphome import (
    read_sandbox_backend,
    resolve_runtime_paths,
    write_sandbox_backend,
)
from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef.sandbox import SandboxResult, SubprocessSandbox
from sentinel_slice.consumer.loop import ConsumerLoop
from sentinel_slice.consumer.native import NativeApprover
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.mcp_gateway import _resolve_sandbox
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
DRAFT = "cap.email.draft_reply.v1"


class _LabelSandbox:
    """A backend that delegates to the real subprocess run but reports a
    custom containment label — lets us prove the label on the receipt came
    from THIS backend without needing a real AppContainer."""

    containment_class = "fake-isolation"

    def __init__(self):
        self.runs = 0

    def run(self, spec):
        self.runs += 1
        return SubprocessSandbox().run(spec)


def _loop(tmp_path, sandbox):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(),
        policy_set=PolicySet([Policy(role="account_manager",
                                     allowed_capabilities=(DRAFT,),
                                     rate_limit_per_hour=20)]),
        store=CashierStore(), public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX), attestor=MockAttestor(),
        window_root=str(tmp_path / "win"), sandbox=sandbox)


def _order():
    return Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                 role="account_manager", capability_id=DRAFT,
                 args={"thread_id": "user.kenji/t-001"},
                 nonce="n-" + uuid.uuid4().hex, ts="2026-06-11T00:00:00+00:00")


def test_loop_uses_its_sandbox_and_records_the_label(tmp_path):
    sandbox = _LabelSandbox()
    loop = _loop(tmp_path, sandbox)
    outcome = loop.place(_order())
    assert outcome.accepted
    assert sandbox.runs == 1                      # the loop used OUR backend
    assert loop.last_chef.receipt.status == "FULFILLED"
    assert loop.last_chef.receipt.containment == "fake-isolation"


def test_consumer_loop_uses_loop_sandbox(tmp_path):
    sandbox = _LabelSandbox()
    consumer = ConsumerLoop(_loop(tmp_path, sandbox),
                            approver=NativeApprover(show_fn=lambda s: "deny"))
    out = consumer.place(_order())   # DRAFT is low-stakes -> no prompt, runs
    assert out.status == "FULFILLED"
    assert sandbox.runs == 1
    assert out.receipt.containment == "fake-isolation"


def test_default_loop_records_subprocess_contract(tmp_path):
    loop = _loop(tmp_path, None)     # no sandbox -> run_chef's default
    loop.place(_order())
    assert loop.last_chef.receipt.containment == "subprocess-contract"


# ---- app-home marker + _resolve_sandbox ----

def test_sandbox_marker_round_trips(tmp_path):
    home = str(tmp_path / "home")
    apphome.ensure_app_home(home)
    assert read_sandbox_backend(home) is None          # none set up
    path = write_sandbox_backend(home, "appcontainer")
    assert os.path.isfile(path)
    assert read_sandbox_backend(home) == "appcontainer"


def test_resolve_sandbox_subprocess_is_none(tmp_path):
    paths = resolve_runtime_paths(home=str(tmp_path / "home"))
    assert _resolve_sandbox("subprocess", paths) is None


def test_resolve_sandbox_auto_without_marker_is_none(tmp_path):
    paths = resolve_runtime_paths(home=str(tmp_path / "home"))
    assert _resolve_sandbox("auto", paths) is None


def test_resolve_sandbox_appcontainer_degrades_when_unavailable(tmp_path, monkeypatch):
    import sentinel_slice.mcp_gateway as gw
    # Force "unavailable" so this is deterministic on every platform.
    monkeypatch.setattr(
        "sentinel_slice.chef.appcontainer.is_available", lambda: False)
    paths = resolve_runtime_paths(home=str(tmp_path / "home"))
    assert _resolve_sandbox("appcontainer", paths) is None


def test_resolve_sandbox_auto_reads_marker(tmp_path, monkeypatch):
    home = str(tmp_path / "home")
    apphome.ensure_app_home(home)
    write_sandbox_backend(home, "appcontainer")
    monkeypatch.setattr(
        "sentinel_slice.chef.appcontainer.is_available", lambda: True)
    paths = resolve_runtime_paths(home=home)
    sandbox = _resolve_sandbox("auto", paths)
    assert sandbox is not None
    assert sandbox.containment_class == "appcontainer"
