# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Capability advisory metadata (v0.3) - inputs the console coaches from.

The console reads recommended_max_rate and requires_second_admin to warn the
operator and gate sensitive publishes, so these must load with exact values.
Older capability files (no advisory keys) must still load with safe defaults.
"""

from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Capability


def test_catalog_loads_enriched_and_highrisk_caps():
    cat = load_catalog()

    draft = cat["cap.email.draft_reply.v1"]
    assert draft.risk_class == "low"
    assert draft.recommended_max_rate == 20
    assert draft.requires_second_admin is False
    assert draft.description != ""

    pay = cat["cap.payment.initiate.v1"]
    assert pay.risk_class == "high"
    assert pay.side_effects == "money_movement"
    assert pay.recommended_max_rate == 2
    assert pay.requires_second_admin is True


def test_capability_defaults_when_advisory_keys_absent():
    # A v0.1-style capability dict (no advisory keys) still constructs, with
    # conservative defaults.
    cap = Capability(
        id="cap.legacy.v1",
        name="Legacy",
        inputs={"x": "string"},
        outputs={"y": "text"},
        side_effects="none",
        scope="own_queue",
        risk_class="low",
    )
    assert cap.description == ""
    assert cap.recommended_max_rate is None
    assert cap.requires_second_admin is False
