"""First-run readiness (v0.13).

readiness() inspects without changing; ensure_ready() brings the home up
idempotently. Side effects are injected, so these tests write no keys and run
no icacls — they assert exactly WHICH actions fire under each starting state.
"""

import os

from sentinel_slice import apphome
from sentinel_slice.app.firstrun import Readiness, ensure_ready, readiness


def test_readiness_on_empty_home(tmp_path):
    home = str(tmp_path / "home")
    r = readiness(home, available_fn=lambda: False)
    assert r == Readiness(home=home, initialized=False,
                          sandbox_available=False, sandbox_enabled=False)


def test_readiness_reports_initialized_and_marker(tmp_path):
    home = str(tmp_path / "home")
    apphome.ensure_app_home(home)
    with open(apphome.private_key_path(home), "wb") as fh:
        fh.write(b"PEM")
    apphome.write_sandbox_backend(home, "appcontainer")
    r = readiness(home, available_fn=lambda: True)
    assert r.initialized is True
    assert r.sandbox_available is True
    assert r.sandbox_enabled is True


def test_ensure_ready_initializes_and_enables_sandbox(tmp_path):
    home = str(tmp_path / "home")
    inited, set_up = [], []

    def fake_init(h):
        # Simulate keygen by dropping a private key where apphome looks.
        apphome.ensure_app_home(h)
        with open(apphome.private_key_path(h), "wb") as fh:
            fh.write(b"PEM")
        inited.append(h)

    def fake_setup(h):
        set_up.append(h)
        return apphome.write_sandbox_backend(h, "appcontainer")

    report = ensure_ready(home, enable_sandbox=True, init_fn=fake_init,
                          sandbox_setup_fn=fake_setup, available_fn=lambda: True)

    assert report["actions"] == ["initialized", "sandbox_enabled"]
    assert report["initialized"] is True
    assert report["sandbox_enabled"] is True
    assert inited == [home] and set_up == [home]


def test_ensure_ready_is_idempotent(tmp_path):
    home = str(tmp_path / "home")

    def fake_init(h):
        apphome.ensure_app_home(h)
        with open(apphome.private_key_path(h), "wb") as fh:
            fh.write(b"PEM")

    def fake_setup(h):
        return apphome.write_sandbox_backend(h, "appcontainer")

    first = ensure_ready(home, init_fn=fake_init, sandbox_setup_fn=fake_setup,
                         available_fn=lambda: True)
    assert first["actions"] == ["initialized", "sandbox_enabled"]
    # Second run: nothing left to do.
    second = ensure_ready(home, init_fn=fake_init, sandbox_setup_fn=fake_setup,
                          available_fn=lambda: True)
    assert second["actions"] == []
    assert second["initialized"] is True
    assert second["sandbox_enabled"] is True


def test_ensure_ready_skips_sandbox_when_unavailable(tmp_path):
    home = str(tmp_path / "home")

    def fake_init(h):
        apphome.ensure_app_home(h)
        with open(apphome.private_key_path(h), "wb") as fh:
            fh.write(b"PEM")

    def fake_setup(h):  # must NOT be called
        raise AssertionError("sandbox setup attempted when unavailable")

    report = ensure_ready(home, enable_sandbox=True, init_fn=fake_init,
                          sandbox_setup_fn=fake_setup, available_fn=lambda: False)
    assert report["actions"] == ["initialized"]
    assert report["sandbox_available"] is False
    assert report["sandbox_enabled"] is False


def test_ensure_ready_respects_disable_sandbox(tmp_path):
    home = str(tmp_path / "home")

    def fake_init(h):
        apphome.ensure_app_home(h)
        with open(apphome.private_key_path(h), "wb") as fh:
            fh.write(b"PEM")

    def fake_setup(h):
        raise AssertionError("sandbox setup attempted when disabled")

    report = ensure_ready(home, enable_sandbox=False, init_fn=fake_init,
                          sandbox_setup_fn=fake_setup, available_fn=lambda: True)
    assert report["actions"] == ["initialized"]
    assert report["sandbox_enabled"] is False
