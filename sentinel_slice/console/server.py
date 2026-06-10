"""Console HTTP transport — thin stdlib server over ConsoleService.

This layer does TRANSPORT ONLY: parse the request, resolve the admin token,
call the matching ConsoleService method, map a ConsoleError to its HTTP status,
serialize JSON. All business logic and authorization live in service.py, so
this file has no policy decisions in it — swapping in FastAPI later replaces
only this module (CONSOLE_SPEC non-negotiable #5).

Binds 127.0.0.1 ONLY. The token arrives in the `X-Admin-Token` header. This is
the in-process trust boundary exposed for an operator UI; it is NOT a hardened
public endpoint (no TLS, MOCK identity) — see CONSOLE_SPEC.

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
from http.server import BaseHTTPRequestHandler, HTTPServer

from sentinel_slice.console.auth import AdminRegistry, default_dev_registry, load_registry
from sentinel_slice.console.service import ConsoleError, BadRequestError

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def make_handler(service, registry: AdminRegistry):
    class Handler(BaseHTTPRequestHandler):
        # quiet default logging in tests
        def log_message(self, *args):  # noqa: D401
            pass

        def _send_json(self, status, obj):
            body = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _admin(self):
            return registry.resolve(self.headers.get("X-Admin-Token"))

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
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
            admin = self._admin()
            if admin is None:
                # Unknown/missing token: 401 before any work.
                self._send_json(401, {"error": "unauthorized", "detail":
                                       "missing or unknown X-Admin-Token"})
                return
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            try:
                result = self._route(method, path, admin)
                self._send_json(200, result)
            except ConsoleError as exc:
                self._send_json(
                    exc.http_status,
                    {"error": type(exc).__name__, "detail": str(exc)},
                )

        def _route(self, method, path, admin):
            if method == "GET":
                if path == "/api/capabilities":
                    return service.capabilities(admin)
                if path == "/api/policies":
                    return service.policies(admin)
                if path == "/api/activity":
                    return service.activity(admin)
                if path.startswith("/api/receipt/"):
                    return service.receipt(admin, _int_tail(path))
                if path == "/" or path == "/index.html":
                    return self._serve_static()
                raise _not_found(path)
            if method == "POST":
                body = self._body()
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
                raise _not_found(path)
            raise _not_found(path)

        def _serve_static(self):
            # Phase 3 ships the page; for now report that the API is up.
            return {
                "console": "Sentinel Loop operator console API",
                "ui": "static page ships in CONSOLE_SPEC phase 3",
                "endpoints": [
                    "GET /api/capabilities", "GET /api/policies",
                    "GET /api/activity", "GET /api/receipt/{seq}",
                    "POST /api/policies/simulate", "POST /api/policies/publish",
                    "POST /api/policies/{seq}/approve",
                    "POST /api/policies/rollback", "POST /api/drill/run",
                ],
            }

        def do_GET(self):
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
    from sentinel_slice.menu.catalog import load_catalog

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
        catalog=load_catalog(),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-console",
        description="Operator console API (MOCK identity, localhost only).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--ledger", default="ledger.db")
    parser.add_argument("--policy-db", default="policy_history.db")
    parser.add_argument("--admins", default=None, help="MOCK admin token config JSON")
    args = parser.parse_args(argv)

    try:
        service = build_default_service(
            ledger_db_path=args.ledger, policy_db_path=args.policy_db
        )
    except FileNotFoundError as exc:
        print(exc)
        return 2

    registry = (
        load_registry(args.admins) if args.admins else default_dev_registry()
    )
    server = make_server(service, registry, host=args.host, port=args.port)
    print(
        "Sentinel console API on http://{}:{}  (MOCK identity — dev tokens: "
        "dev-author-token / dev-reviewer-token)".format(args.host, args.port)
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
