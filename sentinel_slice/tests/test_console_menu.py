# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Console menu curation (v0.7) — a non-technical operator curates the menu.

Service-level + HTTP. Asserts: templates list, creating a capability from a
form (no JSON), it appears on the menu and is orderable, enable/disable moves
it on/off the live menu, built-ins are locked, delete removes it, and the role
gate (only an author curates). Plus an HTTP smoke for create->menu.
"""

import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_store import PolicyStore
from sentinel_slice.console import signed_auth
from sentinel_slice.console.auth import Admin, ROLE_AUTHOR, ROLE_REVIEWER
from sentinel_slice.console.server import make_server
from sentinel_slice.console.service import (
    AuthError,
    BadRequestError,
    ConflictError,
    ConsoleService,
)
from sentinel_slice.menu.catalog import load_catalog

AUTHOR = Admin(id="tanaka", role=ROLE_AUTHOR)
REVIEWER = Admin(id="rao", role=ROLE_REVIEWER)


def _service(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    custom = tmp_path / "custom"
    (tmp_path / "active_policies").mkdir()
    svc = ConsoleService(
        private_key=priv, public_key_pem_path=str(pub),
        ledger_db_path=str(tmp_path / "ledger.db"),
        policy_store=PolicyStore(str(tmp_path / "policy.db"), priv),
        policies_dir=str(tmp_path / "active_policies"),
        catalog=load_catalog(custom_dir=str(custom), include_disabled=True),
        custom_dir=str(custom))
    return svc


def _form(**over):
    base = {"behavior": "docs_summarize",
            "capability_id": "cap.contracts.summarize.v1",
            "name": "Summarize contracts"}
    base.update(over)
    return base


def test_templates_listed(tmp_path):
    svc = _service(tmp_path)
    behaviors = [t["behavior"] for t in svc.templates(AUTHOR)["templates"]]
    assert behaviors == ["docs_summarize", "draft_reply", "payment_request",
                         "template"]
    # The "Custom text response" template behavior advertises it needs a template.
    by = {t["behavior"]: t for t in svc.templates(AUTHOR)["templates"]}
    assert by["template"]["needs_template"] is True
    assert by["draft_reply"]["needs_template"] is False


def test_create_appears_on_menu_and_capabilities(tmp_path):
    svc = _service(tmp_path)
    res = svc.create_capability(AUTHOR, _form())
    assert res["created"] == "cap.contracts.summarize.v1"

    menu_ids = [c["id"] for c in svc.menu(AUTHOR)["capabilities"]]
    assert "cap.contracts.summarize.v1" in menu_ids
    # On the live (orderable) capabilities list too.
    cap_ids = [c["id"] for c in svc.capabilities(AUTHOR)["capabilities"]]
    assert "cap.contracts.summarize.v1" in cap_ids


def test_disable_removes_from_live_menu_but_not_curation(tmp_path):
    svc = _service(tmp_path)
    svc.create_capability(AUTHOR, _form())

    svc.set_capability_enabled(AUTHOR, "cap.contracts.summarize.v1", False)
    # Off the orderable menu...
    assert "cap.contracts.summarize.v1" not in [
        c["id"] for c in svc.capabilities(AUTHOR)["capabilities"]]
    # ...still shown in the curation view, marked off.
    row = next(c for c in svc.menu(AUTHOR)["capabilities"]
               if c["id"] == "cap.contracts.summarize.v1")
    assert row["enabled"] is False and row["editable"] is True


def test_builtins_are_locked(tmp_path):
    svc = _service(tmp_path)
    rows = {c["id"]: c for c in svc.menu(AUTHOR)["capabilities"]}
    assert rows["cap.email.draft_reply.v1"]["editable"] is False
    with pytest.raises(ConflictError):
        svc.set_capability_enabled(AUTHOR, "cap.email.draft_reply.v1", False)
    with pytest.raises(ConflictError):
        svc.delete_capability(AUTHOR, "cap.email.draft_reply.v1")


def test_create_validation_and_duplicate(tmp_path):
    svc = _service(tmp_path)
    with pytest.raises(BadRequestError):
        svc.create_capability(AUTHOR, _form(behavior="nope"))
    svc.create_capability(AUTHOR, _form())
    with pytest.raises(ConflictError):
        svc.create_capability(AUTHOR, _form())   # duplicate id


def test_delete(tmp_path):
    svc = _service(tmp_path)
    svc.create_capability(AUTHOR, _form())
    svc.delete_capability(AUTHOR, "cap.contracts.summarize.v1")
    assert "cap.contracts.summarize.v1" not in [
        c["id"] for c in svc.menu(AUTHOR)["capabilities"]]


def test_only_author_curates(tmp_path):
    svc = _service(tmp_path)
    with pytest.raises(AuthError):
        svc.create_capability(REVIEWER, _form())
    with pytest.raises(AuthError):
        svc.set_capability_enabled(REVIEWER, "x", True)
    # Reviewer CAN read the menu/templates.
    assert svc.menu(REVIEWER)["capabilities"]
    assert svc.templates(REVIEWER)["templates"]


def test_http_create_then_menu(tmp_path):
    svc = _service(tmp_path)
    reg, signers = signed_auth.dev_registry()
    server = make_server(svc, reg, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    base = "http://{}:{}".format(host, port)

    def call(method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(base + path, data=data, method=method)
        for k, v in signed_auth.sign_headers(
                signers["tanaka"], admin_id="tanaka", method=method, path=path,
                body=(data if data is not None else b""), now=time.time()).items():
            req.add_header(k, v)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        s, _ = call("POST", "/api/menu/capabilities",
                    {"behavior": "draft_reply",
                     "capability_id": "cap.support.draft.v1",
                     "name": "Draft support replies"})
        assert s == 200
        s, menu = call("GET", "/api/menu")
        assert s == 200
        assert "cap.support.draft.v1" in [c["id"] for c in menu["capabilities"]]
        s, _ = call("POST",
                    "/api/menu/capabilities/cap.support.draft.v1/disable")
        assert s == 200
    finally:
        server.shutdown()
