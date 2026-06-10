"""SentinelLoop — the credential boundary and the ONLY signing site.

The cashier Ed25519 private key (the credential) is held here and nowhere
else. The loop wires the engine's `spawn` hook to `run_chef`, forcing every
path handed to the chef (`public_key_pem_path`, `fixtures_root`,
`window_root`) to be ABSOLUTE — the chef runs with `cwd=` a throwaway dir, so
relative paths would silently break (Phase-4 footgun). The diner never
imports this module for the key; it only receives a constructed loop handle
and calls `place` / `read_window_draft` / `read_receipts`.

Allowed imports: stdlib, cryptography (key loading inside `build_default`
only), and sentinel_slice.{cashier,menu,ledger,chef,attestor,window,spine}.
The diner module is NOT imported here.
"""

import os
import time

from cryptography.hazmat.primitives import serialization

from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.chef.runner import run_chef
from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.spine.types import order_meta_from_order
from sentinel_slice.window import serving


class SentinelLoop:
    """Owns the cashier private key and the assembled services. The only
    place an Order is signed (indirectly, via process_order)."""

    def __init__(
        self,
        *,
        private_key,
        ledger,
        menu,
        policy_set,
        store,
        public_key_pem_path,
        fixtures_root,
        attestor,
        window_root,
    ):
        # private_key is the credential — it lives ONLY on this instance.
        self.private_key = private_key
        self.ledger = ledger
        self.menu = menu
        self.policy_set = policy_set
        self.store = store
        # Defensively absolutize the three chef-facing paths so the Phase-4
        # footgun (chef cwd=throwaway dir) is impossible to trip.
        self.public_key_pem_path = os.path.abspath(public_key_pem_path)
        self.fixtures_root = os.path.abspath(fixtures_root)
        self.attestor = attestor
        self.window_root = os.path.abspath(window_root)
        self._last_chef = None
        self._current_order_meta = None

    def _spawn(self, ticket):
        """Engine hook: run the chef on the freshly-signed ticket. Records the
        ChefResult onto the instance (process_order discards the return value)
        so `place` can surface the produced draft, and also returns it.

        order_meta rides alongside (NOT inside) the ticket: the Ticket
        signable dict is a frozen Phase-4 contract, and the chef has no
        business knowing the principal anyway — only the receipt does."""
        self._last_chef = run_chef(
            ticket,
            ledger=self.ledger,
            public_key_pem_path=self.public_key_pem_path,
            fixtures_root=self.fixtures_root,
            attestor=self.attestor,
            window_root=self.window_root,
            order_meta=self._current_order_meta,
        )
        return self._last_chef

    def place(self, order):
        """Run an Order through the cashier pipeline. On acceptance the chef
        ran during process_order (via _spawn); on rejection _spawn never ran
        so _last_chef stays None."""
        self._last_chef = None
        self._current_order_meta = order_meta_from_order(order)
        outcome = process_order(
            order,
            menu=self.menu,
            policy_set=self.policy_set,
            store=self.store,
            ledger=self.ledger,
            private_key=self.private_key,
            spawn=self._spawn,
        )
        return outcome

    @property
    def last_chef(self):
        """The ChefResult from the most recent place() that reached the chef,
        or None if the cashier rejected the order before spawn. Lets a caller
        distinguish cashier ACCEPTANCE (outcome.accepted) from chef FULFILLMENT
        (last_chef.returncode == 0 with a draft) — they are NOT the same."""
        return self._last_chef

    def read_window_draft(self, order_id) -> bytes:
        """Read-only helper for the diner: bytes of the produced draft."""
        return serving.read_draft(order_id, self.window_root)

    def read_receipts(self) -> list:
        """Read-only helper for the diner: the full receipt chain."""
        return self.ledger.read_all()


def build_default(
    ledger_db_path: str,
    *,
    window_root: str | None = None,
    keys_dir: str | None = None,
) -> SentinelLoop:
    """Construct a SentinelLoop wired to the cashier key in `keys_dir`
    (default: the committed sentinel_slice/keys) and the real services. This
    factory is the ONLY place the private PEM is read."""
    SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))
    if keys_dir is None:
        keys_dir = os.path.join(SENTINEL_DIR, "keys")
    keys_dir = os.path.abspath(keys_dir)

    private_key_path = os.path.join(keys_dir, "cashier_ed25519_private.pem")
    if not os.path.isfile(private_key_path):
        # Fresh clones do not ship the private key (it is gitignored).
        raise FileNotFoundError(
            "cashier private key not found at {}.\n"
            "Generate a keypair first:  python -m sentinel_slice.keygen\n"
            "NOTE: a fresh keypair cannot verify receipts signed by an older "
            "key - start a new ledger db (see README, 'Fresh clone "
            "bootstrap').".format(private_key_path)
        )
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    public_key_pem_path = os.path.abspath(
        os.path.join(keys_dir, "cashier_ed25519_public.pem")
    )
    fixtures_root = os.path.abspath(
        os.path.join(SENTINEL_DIR, "kitchen", "fixtures", "mailbox")
    )
    if window_root is None:
        window_root = os.path.abspath(os.path.join(SENTINEL_DIR, "window", "orders"))
    else:
        window_root = os.path.abspath(window_root)

    ledger = Ledger(ledger_db_path, private_key)
    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()
    attestor = MockAttestor()

    return SentinelLoop(
        private_key=private_key,
        ledger=ledger,
        menu=menu,
        policy_set=policy_set,
        store=store,
        public_key_pem_path=public_key_pem_path,
        fixtures_root=fixtures_root,
        attestor=attestor,
        window_root=window_root,
    )
