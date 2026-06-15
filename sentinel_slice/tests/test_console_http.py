# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Console HTTP transport e2e — stdlib only, no requests.

Starts the real server on an ephemeral localhost port in a background thread
and drives the full operator loop over HTTP exactly as a browser would, now
authenticating with REAL Ed25519 SIGNED REQUESTS (X-Admin-Id / -Timestamp /
-Signature): author -> simulate -> publish (second-admin) -> reviewer approves
-> activity. Asserts status codes, the policy-store effects, and that the
policy history verifies standalone. Also pins the transport's auth mapping
(401 no signature / unknown id / bad signature, 403 wrong role).
"""

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_store import PolicyStore
from sentinel_slice.console import signed_auth
from sentinel_slice.console.server import make_server
from sentinel_slice.console.service import ConsoleService
from sentinel_slice.menu.catalog import load_catalog

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_POLICY = SENTINEL_DIR / "verify_policy_history.py"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"

AUTHOR_ID, REVIEWER_ID = "tanaka", "reviewer-rao"


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


def _call(base, method, path, *, admin_id=None, signer=None, body=None,
          raw_override=None):
    url = base + path
    data = None if body is None else json.dumps(body).encode("utf-8")
    if raw_override is not None:
        data = raw_override
    req = urllib.request.Request(url, data=data, method=method)
    if signer is not None:
        signed_body = data if data is not None else b""
        for k, v in signed_auth.sign_headers(
                signer, admin_id=admin_id, method=method, path=path,
                body=signed_body, now=time.time()).items():
            req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _run_server(tmp_path):
    svc, pub = _service(tmp_path)
    registry, signers = signed_auth.dev_registry()
    server = make_server(svc, registry, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = "http://{}:{}".format(host, port)
    return server, base, pub, signers


def test_full_operator_loop_over_http(tmp_path):
    server, base, pub, signers = _run_server(tmp_path)
    author, reviewer = signers[AUTHOR_ID], signers[REVIEWER_ID]
    try:
        status, caps = _call(base, "GET", "/api/capabilities",
                             admin_id=AUTHOR_ID, signer=author)
        assert status == 200
        ids = [c["id"] for c in caps["capabilities"]]
        assert DRAFT in ids and PAY in ids

        status, sim = _call(base, "POST", "/api/policies/simulate",
                            admin_id=AUTHOR_ID, signer=author,
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

        status, pub1 = _call(base, "POST", "/api/policies/publish",
                             admin_id=AUTHOR_ID, signer=author,
                             body={"candidate_policy": [{
                                 "role": "account_manager",
                                 "allowed_capabilities": [DRAFT],
                                 "rate_limit_per_hour": 5}],
                                 "reason": "baseline"})
        assert status == 200 and pub1["status"] == "active"

        status, pub2 = _call(base, "POST", "/api/policies/publish",
                             admin_id=AUTHOR_ID, signer=author,
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
                          admin_id=AUTHOR_ID, signer=author)
        assert status == 403

        # reviewer approves -> 200, active.
        status, appr = _call(base, "POST",
                             "/api/policies/{}/approve".format(pending_seq),
                             admin_id=REVIEWER_ID, signer=reviewer)
        assert status == 200 and appr["status"] == "active"
        assert appr["approved_by"] == REVIEWER_ID

        status, pol = _call(base, "GET", "/api/policies",
                            admin_id=REVIEWER_ID, signer=reviewer)
        assert status == 200
        assert pol["active"]["policies"][0]["allowed_capabilities"] == [DRAFT, PAY]

        status, act = _call(base, "GET", "/api/activity",
                            admin_id=REVIEWER_ID, signer=reviewer)
        assert status == 200 and act["receipts_total"] == 0
    finally:
        server.shutdown()

    proc = subprocess.run(
        [sys.executable, str(VERIFY_POLICY),
         str(tmp_path / "policy.db"), str(pub)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=3"


def test_http_auth_mapping(tmp_path):
    server, base, _pub, signers = _run_server(tmp_path)
    author, reviewer = signers[AUTHOR_ID], signers[REVIEWER_ID]
    # A real keypair NOT in the registry.
    outsider, _ = signed_auth.generate_admin("author")
    try:
        # No signature headers -> 401.
        status, _ = _call(base, "GET", "/api/capabilities")
        assert status == 401
        # Unknown admin id (signed, but id not registered) -> 401.
        status, _ = _call(base, "GET", "/api/capabilities",
                          admin_id="ghost", signer=outsider)
        assert status == 401
        # Registered id but signed with the WRONG key -> 401 (bad signature).
        status, _ = _call(base, "GET", "/api/capabilities",
                          admin_id=AUTHOR_ID, signer=outsider)
        assert status == 401
        # Reviewer publishing -> 403 (wrong role, identity is valid).
        status, _ = _call(base, "POST", "/api/policies/publish",
                          admin_id=REVIEWER_ID, signer=reviewer,
                          body={"candidate_policy": [{
                              "role": "account_manager",
                              "allowed_capabilities": [DRAFT],
                              "rate_limit_per_hour": 5}], "reason": "x"})
        assert status == 403
        # Unknown route (validly signed) -> 404.
        status, _ = _call(base, "GET", "/api/nope",
                          admin_id=AUTHOR_ID, signer=author)
        assert status == 404
        # Validly-signed but non-JSON body -> 400 (auth passes, parse fails).
        status, _ = _call(base, "POST", "/api/policies/publish",
                          admin_id=AUTHOR_ID, signer=author,
                          raw_override=b"{not json")
        assert status == 400
    finally:
        server.shutdown()
