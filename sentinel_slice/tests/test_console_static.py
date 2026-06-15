"""Console static page is served safely and is self-contained.

The console is the highest-value target, so the page that drives it must:
- load WITHOUT identity (it's what lets the operator load their key), while
  every /api route still requires a valid SIGNED request;
- carry a strict Content-Security-Policy (no external origins, no inline
  script) and nosniff/frame-deny headers;
- reference NO external URL anywhere in its markup or script (zero network
  egress — the tool that watches must not phone home).
"""

import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_store import PolicyStore
from sentinel_slice.console import signed_auth
from sentinel_slice.console.server import make_server
from sentinel_slice.console.service import ConsoleService
from sentinel_slice.menu.catalog import load_catalog

STATIC_DIR = Path(__file__).resolve().parents[1] / "console" / "static"


def _server(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    (tmp_path / "active_policies").mkdir()
    svc = ConsoleService(
        private_key=priv, public_key_pem_path=str(pub),
        ledger_db_path=str(tmp_path / "ledger.db"),
        policy_store=PolicyStore(str(tmp_path / "policy.db"), priv),
        policies_dir=str(tmp_path / "active_policies"),
        catalog=load_catalog())
    registry, signers = signed_auth.dev_registry()
    server = make_server(svc, registry, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, "http://{}:{}".format(host, port), signers["tanaka"]


def _get(url, signer=None):
    req = urllib.request.Request(url, method="GET")
    if signer is not None:
        path = urlsplit(url).path
        for k, v in signed_auth.sign_headers(
                signer, admin_id="tanaka", method="GET", path=path,
                body=b"", now=time.time()).items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8")


def test_index_served_without_identity_with_csp(tmp_path):
    server, base, _signer = _server(tmp_path)
    try:
        status, headers, body = _get(base + "/")  # no identity
        assert status == 200
        assert "text/html" in headers["Content-Type"]
        csp = headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp
        assert "script-src 'self'" in csp
        assert "connect-src 'self'" in csp
        assert "'unsafe-eval'" not in csp
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "<title>Sentinel Loop" in body
    finally:
        server.shutdown()


def test_appjs_served_self_origin(tmp_path):
    server, base, _signer = _server(tmp_path)
    try:
        status, headers, body = _get(base + "/app.js")
        assert status == 200
        assert "javascript" in headers["Content-Type"]
        # The script authenticates with a SIGNED request, not a bearer token.
        assert "X-Admin-Signature" in body
    finally:
        server.shutdown()


def test_api_still_requires_signature_even_though_page_does_not(tmp_path):
    server, base, signer = _server(tmp_path)
    try:
        # The page loads with no identity...
        assert _get(base + "/")[0] == 200
        # ...but the data API does not.
        assert _get(base + "/api/capabilities")[0] == 401
        assert _get(base + "/api/capabilities", signer=signer)[0] == 200
    finally:
        server.shutdown()


def test_static_files_have_no_external_urls():
    """Zero network egress: neither the page nor the script references any
    external origin (http(s)://...). Local/relative refs and a SECURITY-doc
    'do not' mention are fine; an actual external resource URL is not."""
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    pattern = re.compile(r"https?://(?!127\.0\.0\.1|localhost)", re.IGNORECASE)
    assert not pattern.search(html), "index.html references an external URL"
    assert not pattern.search(js), "app.js references an external URL"
