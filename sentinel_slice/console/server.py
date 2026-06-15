"""Console HTTP transport — thin stdlib server over ConsoleService.

This layer does TRANSPORT ONLY: parse the request, resolve the admin token,
call the matching ConsoleService method, map a ConsoleError to its HTTP status,
serialize JSON. All business logic and authorization live in service.py, so
this file has no policy decisions in it — swapping in FastAPI later replaces
only this module (CONSOLE_SPEC non-negotiable #5).

Binds 127.0.0.1 ONLY. Identity is REAL Ed25519 request signing (see
signed_auth.py): every /api request carries X-Admin-Id / X-Admin-Timestamp /
X-Admin-Signature, verified against a registry of admin PUBLIC keys. It is
still not a hardened public endpoint (no TLS) — it is the operator's localhost
control plane.

Routes:
    GET  /api/capabilities
    GET  /api/policies
    GET  /api/activity
    GET  /api/receipt/{seq}
    POST /api/policies/simulate     {candidate_policy, sample_orders}
    POST /api/policies/publish      {candidate_policy, reason}
    POST /api/policies/{seq}/approve
    POST /api/policies/rollback     {target_seq, reason}
    POST /api/drill/run
    GET  /                          static console page (Phase 3)
"""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from sentinel_slice.console import signed_auth
from sentinel_slice.console.signed_auth import KeyRegistry
from sentinel_slice.console.service import ConsoleError, BadRequestError

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Strict CSP for the console page: same-origin only, NO external origins, NO
# inline scripts (script-src 'self' — app.js is a separate same-origin file).
# This is the air-gap honored in the browser: the page that watches the agents
# can load and reach nothing but this localhost origin. style-src allows inline
# CSS only (low risk; no inline <script> is permitted).
_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def make_handler(service, registry: KeyRegistry):
    class Handler(BaseHTTPRequestHandler):
        # quiet default logging in tests
        def log_message(self, *args):  # noqa: D401
            pass

        def _security_headers(self):
            # Applied to every response. CSP enforces the air gap in the
            # browser; nosniff/frame-deny are belt-and-suspenders.
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")

        def _send_json(self, status, obj):
            body = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _send_static(self, path):
            """Serve the self-contained console page/script. No identity needed
            to fetch the page — it carries no data and is what lets the operator
            load their key; every /api call it then makes is a SIGNED request.
            Returns True if handled."""
            entry = _STATIC_FILES.get(path)
            if entry is None:
                return False
            filename, ctype = entry
            try:
                with open(os.path.join(_STATIC_DIR, filename), "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send_json(404, {"error": "NotFound", "detail": filename})
                return True
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)
            return True

        def _raw_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def _parse_body(self, raw):
            if not raw:
                return {}
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise BadRequestError("request body is not valid JSON")
            if not isinstance(obj, dict):
                raise BadRequestError("request body must be a JSON object")
            return obj

        def _dispatch(self, method):
            # Read the raw body FIRST: the signature covers it. Then verify the
            # signed request against the registry of admin public keys.
            raw = self._raw_body() if method == "POST" else b""
            admin = signed_auth.verify(
                registry, method=method, path=self.path, body=raw,
                header=self.headers.get, now=time.time())
            if admin is None:
                # Missing/invalid/stale signature, or unknown id: 401, no work.
                self._send_json(401, {"error": "unauthorized", "detail":
                                       "missing or invalid signed request"})
                return
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            try:
                result = self._route(method, path, admin, raw)
                self._send_json(200, result)
            except ConsoleError as exc:
                self._send_json(
                    exc.http_status,
                    {"error": type(exc).__name__, "detail": str(exc)},
                )

        def _route(self, method, path, admin, raw=b""):
            if method == "GET":
                if path == "/api/capabilities":
                    return service.capabilities(admin)
                if path == "/api/policies":
                    return service.policies(admin)
                if path == "/api/activity":
                    return service.activity(admin)
                if path.startswith("/api/receipt/"):
                    return service.receipt(admin, _int_tail(path))
                if path == "/api/menu/templates":
                    return service.templates(admin)
                if path == "/api/menu":
                    return service.menu(admin)
                raise _not_found(path)
            if method == "POST":
                body = self._parse_body(raw)
                if path == "/api/policies/simulate":
                    return service.simulate(
                        admin,
                        body.get("candidate_policy"),
                        body.get("sample_orders"),
                    )
                if path == "/api/policies/publish":
                    return service.publish(
                        admin, body.get("candidate_policy"), body.get("reason")
                    )
                if path == "/api/policies/rollback":
                    return service.rollback(
                        admin, body.get("target_seq"), body.get("reason")
                    )
                if path.startswith("/api/policies/") and path.endswith("/approve"):
                    seq = _int_segment(path, -2)
                    return service.approve(admin, seq)
                if path == "/api/drill/run":
                    return service.run_drill(admin)
                if path == "/api/menu/capabilities":
                    return service.create_capability(admin, body)
                if path.startswith("/api/menu/capabilities/") and path.endswith("/enable"):
                    return service.set_capability_enabled(
                        admin, _str_segment(path, -2), True)
                if path.startswith("/api/menu/capabilities/") and path.endswith("/disable"):
                    return service.set_capability_enabled(
                        admin, _str_segment(path, -2), False)
                if path.startswith("/api/menu/capabilities/") and path.endswith("/delete"):
                    return service.delete_capability(admin, _str_segment(path, -2))
                raise _not_found(path)
            raise _not_found(path)

        def do_GET(self):
            # Static console page/script load WITHOUT identity (they carry no
            # data and are what lets the operator load their key). All /api
            # routes still require a valid SIGNED request via _dispatch.
            path = self.path.split("?", 1)[0]
            if path in _STATIC_FILES:
                self._send_static(path)
                return
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def _not_found(path):
    from sentinel_slice.console.service import NotFoundError

    return NotFoundError("no route for {}".format(path))


def _int_tail(path):
    return _int_segment(path, -1)


def _int_segment(path, index):
    from sentinel_slice.console.service import BadRequestError as _BR

    try:
        return int(path.strip("/").split("/")[index])
    except (ValueError, IndexError):
        raise _BR("expected an integer path segment in {}".format(path))


def _str_segment(path, index):
    from sentinel_slice.console.service import BadRequestError as _BR

    try:
        return path.strip("/").split("/")[index]
    except IndexError:
        raise _BR("missing path segment in {}".format(path))


def make_server(service, registry, host="127.0.0.1", port=0):
    """Build a single-threaded HTTPServer bound to host:port (port 0 =
    ephemeral). Single-threaded ON PURPOSE: it serializes requests so the
    append-only, hash-chained policy store can never have two concurrent
    publishes race on prev_hash and fork the chain. A localhost operator
    console has no throughput need that would justify the risk."""
    handler = make_handler(service, registry)
    return HTTPServer((host, port), handler)


def build_default_service(
    *,
    ledger_db_path="ledger.db",
    policy_db_path="policy_history.db",
    policies_dir=None,
    keys_dir=None,
):
    """Wire a ConsoleService from the committed keys + the package catalog,
    mirroring loop.build_default. The console owns `policies_dir` (it
    materializes the active version there)."""
    from cryptography.hazmat.primitives import serialization as _ser

    from sentinel_slice.authoring.policy_store import PolicyStore
    from sentinel_slice.console.service import ConsoleService
    from sentinel_slice.menu.catalog import CUSTOM_CAPABILITIES_DIR, load_catalog

    sentinel_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if keys_dir is None:
        keys_dir = os.path.join(sentinel_dir, "keys")
    priv_path = os.path.join(keys_dir, "cashier_ed25519_private.pem")
    if not os.path.isfile(priv_path):
        raise FileNotFoundError(
            "cashier private key not found at {}. Run "
            "`python -m sentinel_slice.keygen` first.".format(priv_path)
        )
    with open(priv_path, "rb") as fh:
        private_key = _ser.load_pem_private_key(fh.read(), password=None)
    pub_path = os.path.join(keys_dir, "cashier_ed25519_public.pem")

    if policies_dir is None:
        policies_dir = os.path.join(sentinel_dir, "console", "active_policies")
    os.makedirs(policies_dir, exist_ok=True)

    return ConsoleService(
        private_key=private_key,
        public_key_pem_path=pub_path,
        ledger_db_path=ledger_db_path,
        policy_store=PolicyStore(policy_db_path, private_key),
        policies_dir=policies_dir,
        catalog=load_catalog(custom_dir=CUSTOM_CAPABILITIES_DIR, include_disabled=True),
        custom_dir=CUSTOM_CAPABILITIES_DIR,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-console",
        description="Operator console API (real Ed25519 signed-request "
        "identity, localhost only).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--ledger", default="ledger.db")
    parser.add_argument("--policy-db", default="policy_history.db")
    parser.add_argument("--admins", default=None,
                        help="JSON registry of admin PUBLIC keys "
                        '({"admins": {"<id>": {"pubkey_pem": "...", '
                        '"role": "author|reviewer"}}})')
    parser.add_argument("--dev-keys-dir", default="console_dev_admins",
                        help="where to write generated DEV admin private keys "
                        "when --admins is not given")
    args = parser.parse_args(argv)

    try:
        service = build_default_service(
            ledger_db_path=args.ledger, policy_db_path=args.policy_db
        )
    except FileNotFoundError as exc:
        print(exc)
        return 2

    if args.admins:
        registry = KeyRegistry.from_file(args.admins)
        key_note = "admin public keys loaded from " + args.admins
    else:
        # Dev bootstrap: generate REAL admin keypairs and write the private
        # keys to disk so the operator can load one in the browser. These are
        # freshly generated each run (gitignored), not committed secrets.
        from cryptography.hazmat.primitives import serialization as _ser

        registry, signers = signed_auth.dev_registry()
        os.makedirs(args.dev_keys_dir, exist_ok=True)
        lines = []
        for admin_id, priv in signers.items():
            path = os.path.join(args.dev_keys_dir, admin_id + ".private.pem")
            with open(path, "wb") as fh:
                fh.write(priv.private_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PrivateFormat.PKCS8,
                    encryption_algorithm=_ser.NoEncryption()))
            lines.append("    {} ({}): {}".format(
                admin_id, registry.get(admin_id).role, os.path.abspath(path)))
        key_note = ("DEV identity — REAL Ed25519 admin keypairs generated this "
                    "run. Load a private key in the browser to authenticate:\n"
                    + "\n".join(lines))

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "WARNING: binding {} is NOT loopback. The console is the highest-"
            "value target and is designed for localhost / the operator's own "
            "machine, with no TLS. Exposing it off-host is unsafe in the "
            "slice.".format(args.host)
        )
    server = make_server(service, registry, host=args.host, port=args.port)
    print(
        "Sentinel operator console on http://{}:{}\n  {}".format(
            args.host, args.port, key_note)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
