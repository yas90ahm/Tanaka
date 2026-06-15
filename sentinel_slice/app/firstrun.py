# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""First-run readiness — make the app usable before showing the door.

A non-technical user opens the app; it must already have done what
`sentinel-init [--sandbox]` does on the command line: an app home with a
keypair, and (on Windows, when available) the OS containment set up. This
module reports readiness and brings the app up to it — idempotently, so
opening the app twice is harmless.

The side-effecting steps (keygen, ACL grants) are injectable so the logic is
testable without writing keys or running icacls; the real defaults call the
already-built `init_app` and the AppContainer setup.
"""

from dataclasses import dataclass

from sentinel_slice import apphome


@dataclass(frozen=True)
class Readiness:
    home: str
    initialized: bool          # app home has a keypair
    sandbox_available: bool     # an OS containment backend exists here
    sandbox_enabled: bool       # ...and the user has it set up (marker present)


def readiness(home: str, *, available_fn=None) -> Readiness:
    """Inspect the app home without changing anything."""
    if available_fn is None:
        from sentinel_slice.chef import appcontainer
        available_fn = appcontainer.is_available
    return Readiness(
        home=home,
        initialized=apphome.is_initialized(home),
        sandbox_available=bool(available_fn()),
        sandbox_enabled=apphome.read_sandbox_backend(home) is not None,
    )


def ensure_ready(
    home: str,
    *,
    enable_sandbox: bool = True,
    init_fn=None,
    sandbox_setup_fn=None,
    available_fn=None,
) -> dict:
    """Bring the app home to a usable state. Idempotent. Returns a report of
    what was done and the resulting readiness.

    - If not initialized, run first-time init (keypair + dirs).
    - If `enable_sandbox` and a containment backend is available but not yet
      enabled, set it up and record the marker.

    The two side-effecting actions are injected (defaults: the real ones) so
    tests don't write keys or touch ACLs."""
    apphome.ensure_app_home(home)

    if available_fn is None:
        from sentinel_slice.chef import appcontainer
        available_fn = appcontainer.is_available
    if init_fn is None:
        from sentinel_slice.init_app import main as _init_main

        def init_fn(h):
            return _init_main(["--home", h], print_fn=lambda *_: None)
    if sandbox_setup_fn is None:
        def sandbox_setup_fn(h):
            from sentinel_slice.chef.appcontainer import AppContainerSandbox
            AppContainerSandbox.setup()
            return apphome.write_sandbox_backend(h, "appcontainer")

    actions = []
    before = readiness(home, available_fn=available_fn)

    if not before.initialized:
        init_fn(home)
        actions.append("initialized")

    sandbox_enabled = before.sandbox_enabled
    if enable_sandbox and before.sandbox_available and not before.sandbox_enabled:
        sandbox_setup_fn(home)
        sandbox_enabled = True
        actions.append("sandbox_enabled")

    after = readiness(home, available_fn=available_fn)
    return {
        "home": home,
        "actions": actions,
        "initialized": after.initialized,
        "sandbox_available": after.sandbox_available,
        "sandbox_enabled": after.sandbox_enabled,
    }
