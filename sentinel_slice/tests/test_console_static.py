"""Console static page is served safely and is self-contained (v0.3 phase 3).

The console is the highest-value target, so the page that drives it must:
- load WITHOUT a token (it's what lets the operator enter one), while every
  /api route still requires the token;
- carry a strict Content-Security-Policy (no external origins, no inline
  script) and nosniff/frame-deny headers;
- reference NO external URL anywhere in its markup or script (zero network
  egress — the tool that watches must not phone home).
"""

import re
import threading
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_store import PolicyStore
from sentinel_slice.console.auth import Admin, AdminRegistry, ROLE_AUTHOR
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
    reg = AdminRegistry({"tok-a": Admin(id="tanaka", role=ROLE_AUTHOR)})
    server = make_server(svc, reg, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, "http://{}:{}".format(host, port)


def _get(url, token=None):
    req = urllib.request.Request(url, method="GET")
    if token:
        req.add_header("X-Admin-Token", token)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8")


def test_index_served_without_token_with_csp(tmp_path):
    server, base = _server(tmp_path)
    try:
        status, headers, body = _get(base + "/")  # no token
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
    server, base = _server(tmp_path)
    try:
        status, headers, body = _get(base + "/app.js")
        assert status == 200
        assert "javascript" in headers["Content-Type"]
        assert "X-Admin-Token" in body  # it does call the API with the header
    finally:
        server.shutdown()


def test_api_still_requires_token_even_though_page_does_not(tmp_path):
    server, base = _server(tmp_path)
    try:
        # The page loads with no token...
        assert _get(base + "/")[0] == 200
        # ...but the data API does not.
        assert _get(base + "/api/capabilities")[0] == 401
        assert _get(base + "/api/capabilities", token="tok-a")[0] == 200
    finally:
        server.shutdown()


def test_static_files_have_no_external_urls():
    """Zero network egress: neither the page nor the script references any
    external origin (http(s)://...). Local/relative refs and the SECURITY-doc
    'do not' mention are fine; an actual external resource URL is not."""
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    # Any occurrence of an absolute external URL fails. We allow the string
    # 'https://...' ONLY if it never appears — strict on purpose.
    pattern = re.compile(r"https?://(?!127\.0\.0\.1|localhost)", re.IGNORECASE)
    assert not pattern.search(html), "index.html references an external URL"
    assert not pattern.search(js), "app.js references an external URL"
