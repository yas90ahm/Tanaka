"""App model (v0.13) — the data/actions behind the door's screens, headless.

Connect rows + toggle round-trip a real host config; permission rows reflect
defaults and persist explicit changes; activity reads the app-home ledger
through the inspector (empty when there are no orders, populated after a real
order, and naming a refusal). No tkinter here — the shell is just a view.
"""

import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice import apphome
from sentinel_slice.app import connect
from sentinel_slice.app.model import AppModel
from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.consumer.preferences import BLOCK
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

PAY = "cap.payment.initiate.v1"
DRAFT = "cap.email.draft_reply.v1"


def _home(tmp_path):
    home = str(tmp_path / "home")
    apphome.ensure_app_home(home)
    return home


def test_connect_rows_and_toggle_round_trip(tmp_path, monkeypatch):
    home = _home(tmp_path)
    host = connect.McpHost(
        "claude_desktop", "Claude Desktop",
        str(tmp_path / "Claude" / "claude_desktop_config.json"))
    monkeypatch.setattr(connect, "known_hosts",
                        lambda environ=None, platform=None: [host])

    model = AppModel(home)
    rows = model.connect_rows()
    assert rows[0]["connected"] is False

    assert model.toggle_connection("claude_desktop") == "added"
    assert model.connect_rows()[0]["connected"] is True
    # Toggling again disconnects.
    assert model.toggle_connection("claude_desktop") == "removed"
    assert model.connect_rows()[0]["connected"] is False


def test_permission_rows_default_then_explicit(tmp_path):
    home = _home(tmp_path)
    model = AppModel(home)
    rows = {r["id"]: r for r in model.permission_rows()}
    # Payment is high-stakes -> default ASK; and it's a default, not explicit.
    assert rows[PAY]["state"] == "ask"
    assert rows[PAY]["is_default"] is True
    assert rows[PAY]["state_label"] == "Ask each time"

    saved = model.set_permission(PAY, BLOCK)
    assert os.path.isfile(saved)
    # A fresh model (reloads the file) sees the persisted explicit choice.
    rows2 = {r["id"]: r for r in AppModel(home).permission_rows()}
    assert rows2[PAY]["state"] == "block"
    assert rows2[PAY]["is_default"] is False


def test_activity_empty_before_any_order(tmp_path):
    home = _home(tmp_path)
    model = AppModel(home)
    report = model.activity_report()
    assert report["empty"] is True
    assert report["fulfilled"] == 0 and report["rejected"] == 0
    assert "No activity yet" in model.activity_text()


def test_activity_reflects_real_orders(tmp_path):
    home = _home(tmp_path)
    # Build a loop writing into the app home's ledger + keys.
    priv = Ed25519PrivateKey.generate()
    apphome_keys = apphome.keys_dir(home)
    pub_path = apphome.public_key_path(home)
    with open(pub_path, "wb") as fh:
        fh.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    sentinel_dir = os.path.dirname(os.path.dirname(os.path.abspath(apphome.__file__)))
    mailbox = os.path.join(
        os.path.dirname(apphome.__file__), "kitchen", "fixtures", "mailbox")
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(apphome.ledger_path(home), priv),
        menu=load_catalog(),
        policy_set=PolicySet([Policy(role="account_manager",
                                     allowed_capabilities=(DRAFT,),
                                     rate_limit_per_hour=20)]),
        store=CashierStore(), public_key_pem_path=pub_path,
        fixtures_root=mailbox, attestor=MockAttestor(),
        window_root=apphome.window_root(home))

    def _order(thread):
        return Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                     role="account_manager", capability_id=DRAFT,
                     args={"thread_id": thread}, nonce="n-" + uuid.uuid4().hex,
                     ts="2026-06-11T00:00:00+00:00")

    loop.place(_order("user.kenji/t-001"))          # FULFILLED
    loop.place(_order("user.victim/x"))             # REJECTED OUT_OF_SCOPE

    report = AppModel(home).activity_report()
    assert report["empty"] is False
    assert report["chain_valid"] is True
    assert report["fulfilled"] == 1
    assert report["rejected"] == 1
    # The scope refusal surfaces as a finding (deterministic inspector rule).
    codes = {f["code"] for f in report["findings"]}
    assert "OUT_OF_SCOPE_ATTEMPTS" in codes or "SCOPE_VIOLATIONS" in codes
