"""Console HTTP transport e2e (v0.3 phase 2) — stdlib only, no requests.

Starts the real server on an ephemeral localhost port in a background thread
and drives the full operator loop over HTTP exactly as a browser would:
author -> simulate -> publish (second-admin) -> reviewer approves -> activity.
Asserts status codes, the policy-store effects, and that the policy history
verifies standalone afterward. Also pins the transport's auth mapping
(401 unknown token, 403 wrong role).
"""

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_store import PolicyStore
from sentinel_slice.console.auth import Admin, AdminRegistry, ROLE_AUTHOR, ROLE_REVIEWER
from sentinel_slice.console.server import make_server
from sentinel_slice.console.service import ConsoleService
from sentinel_slice.menu.catalog import load_catalog

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_POLICY = SENTINEL_DIR / "verify_policy_history.py"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"

A_TOK, R_TOK = "tok-author", "tok-reviewer"


def _registry():
    return AdminRegistry({
        A_TOK: Admin(id="tanaka", role=ROLE_AUTHOR),
        R_TOK: Admin(id="rao", role=ROLE_REVIEWER),
    })


def _service(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    (tmp_path / "active_policies").mkdir()
    svc = ConsoleService(
        private_key=priv,
        public_key_pem_path=str(pub),
        ledger_db_path=str(tmp_path / "ledger.db"),
        policy_store=PolicyStore(str(tmp_path / "policy.db"), priv),
        policies_dir=str(tmp_path / "active_policies"),
        catalog=load_catalog(),
    )
    return svc, pub


def _call(base, method, path, token=None, body=None):
    url = base + path
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if token is not None:
        req.add_header("X-Admin-Token", token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _run_server(tmp_path):
    svc, pub = _service(tmp_path)
    server = make_server(svc, _registry(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = "http://{}:{}".format(host, port)
    return server, base, svc, pub


def test_full_operator_loop_over_http(tmp_path):
    server, base, svc, pub = _run_server(tmp_path)
    try:
        # capabilities readable by the author.
        status, caps = _call(base, "GET", "/api/capabilities", token=A_TOK)
        assert status == 200
        ids = [c["id"] for c in caps["capabilities"]]
        assert DRAFT in ids and PAY in ids

        # simulate (no writes).
        status, sim = _call(base, "POST", "/api/policies/simulate", token=A_TOK,
                            body={"candidate_policy": [{
                                "role": "account_manager",
                                "allowed_capabilities": [DRAFT],
                                "rate_limit_per_hour": 5}],
                                "sample_orders": [{
                                    "principal": "user.kenji",
                                    "role": "account_manager",
                                    "capability_id": DRAFT,
                                    "args": {"thread_id": "user.kenji/t-001"}}]})
        assert status == 200
        assert sim["results"][0]["allowed"] is True

        # publish baseline (active immediately).
        status, pub1 = _call(base, "POST", "/api/policies/publish", token=A_TOK,
                             body={"candidate_policy": [{
                                 "role": "account_manager",
                                 "allowed_capabilities": [DRAFT],
                                 "rate_limit_per_hour": 5}],
                                 "reason": "baseline"})
        assert status == 200 and pub1["status"] == "active"

        # publish a payments policy -> pending (second admin needed).
        status, pub2 = _call(base, "POST", "/api/policies/publish", token=A_TOK,
                             body={"candidate_policy": [{
                                 "role": "account_manager",
                                 "allowed_capabilities": [DRAFT, PAY],
                                 "rate_limit_per_hour": 5}],
                                 "reason": "add payments"})
        assert status == 200 and pub2["status"] == "pending"
        pending_seq = pub2["seq"]

        # author cannot approve own pending change -> 403.
        status, _ = _call(base, "POST",
                          "/api/policies/{}/approve".format(pending_seq),
                          token=A_TOK)
        assert status == 403

        # reviewer approves -> 200, active.
        status, appr = _call(base, "POST",
                             "/api/policies/{}/approve".format(pending_seq),
                             token=R_TOK)
        assert status == 200 and appr["status"] == "active"
        assert appr["approved_by"] == "rao"

        # policies endpoint shows payments now active.
        status, pol = _call(base, "GET", "/api/policies", token=R_TOK)
        assert status == 200
        assert pol["active"]["policies"][0]["allowed_capabilities"] == [DRAFT, PAY]

        # activity readable, empty live ledger -> 0 receipts.
        status, act = _call(base, "GET", "/api/activity", token=R_TOK)
        assert status == 200 and act["receipts_total"] == 0
    finally:
        server.shutdown()

    # The policy history the loop produced verifies standalone.
    proc = subprocess.run(
        [sys.executable, str(VERIFY_POLICY),
         str(tmp_path / "policy.db"), str(pub)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    # baseline + pending + approved-active = 3 versions.
    assert proc.stdout.strip() == "OK verified=3"


def test_http_auth_mapping(tmp_path):
    server, base, _svc, _pub = _run_server(tmp_path)
    try:
        # No token -> 401.
        status, _ = _call(base, "GET", "/api/capabilities")
        assert status == 401
        # Unknown token -> 401.
        status, _ = _call(base, "GET", "/api/capabilities", token="bogus")
        assert status == 401
        # Reviewer publishing -> 403 (wrong role).
        status, _ = _call(base, "POST", "/api/policies/publish", token=R_TOK,
                          body={"candidate_policy": [{
                              "role": "account_manager",
                              "allowed_capabilities": [DRAFT],
                              "rate_limit_per_hour": 5}], "reason": "x"})
        assert status == 403
        # Unknown route -> 404.
        status, _ = _call(base, "GET", "/api/nope", token=A_TOK)
        assert status == 404
        # Bad JSON body -> 400.
        req = urllib.request.Request(
            base + "/api/policies/publish", data=b"{not json",
            method="POST", headers={"X-Admin-Token": A_TOK,
                                    "Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req)
            assert False, "expected HTTPError"
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
