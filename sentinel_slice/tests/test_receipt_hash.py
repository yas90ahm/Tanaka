import dataclasses

from sentinel_slice.spine.types import Receipt
from sentinel_slice.spine.hashing import (
    GENESIS_PREV_HASH,
    receipt_content_dict,
    receipt_content_hash,
)


BASELINE = Receipt(
    receipt_id="r-0001",
    order_id="o-0001",
    ticket_id="t-0001",
    status="FULFILLED",
    reason_code=None,
    result_digest="d" * 64,
    attestation={"mock": True, "measurement": "abc123"},
    prev_hash=GENESIS_PREV_HASH,
    this_hash="PLACEHOLDER",
    sig=b"PLACEHOLDER",
)


def test_genesis_prev_hash_literal():
    # GENESIS_PREV_HASH is DEFINED (contract §3.3, CLAUDE.md) as
    # hashlib.sha256(b"GENESIS").hexdigest(). Its true value is
    # 901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a.
    # The contract draft also pasted "af555..." as the literal, but that
    # string is NOT sha256(b"GENESIS") -- the binding definition is the
    # expression, so this asserts the real digest.
    assert GENESIS_PREV_HASH == "901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a"


def test_content_dict_excludes_this_hash_and_sig():
    cd = receipt_content_dict(BASELINE)
    assert set(cd.keys()) == {
        "receipt_id", "order_id", "ticket_id", "status",
        "reason_code", "result_digest", "attestation", "prev_hash",
    }
    assert "this_hash" not in cd
    assert "sig" not in cd


def test_content_dict_exact_value():
    assert receipt_content_dict(BASELINE) == {
        "receipt_id": "r-0001",
        "order_id": "o-0001",
        "ticket_id": "t-0001",
        "status": "FULFILLED",
        "reason_code": None,
        "result_digest": "d" * 64,
        "attestation": {"mock": True, "measurement": "abc123"},
        # BASELINE.prev_hash is set from the GENESIS_PREV_HASH symbol, whose
        # true sha256(b"GENESIS") value is the 901131... digest below (see
        # test_genesis_prev_hash_literal for why the draft's af555... literal
        # is rejected).
        "prev_hash": "901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a",
    }


def test_baseline_hash_is_stable_hex():
    h = receipt_content_hash(receipt_content_dict(BASELINE))
    assert len(h) == 64
    assert h == h.lower()
    assert all(c in "0123456789abcdef" for c in h)
    assert receipt_content_hash(receipt_content_dict(BASELINE)) == h


def test_baseline_hash_exact_literal():
    assert receipt_content_hash(receipt_content_dict(BASELINE)) == \
        "bfcf09ebf46eda585fc31c654762e0ba59c0779625eb53280d7d74d2d098b830"


def test_hash_changes_when_each_content_field_mutated():
    base_hash = receipt_content_hash(receipt_content_dict(BASELINE))

    mutations = {
        "receipt_id":   "r-9999",
        "order_id":     "o-9999",
        "ticket_id":    "t-9999",
        "status":       "REJECTED",
        "reason_code":  "OFF_MENU",
        "result_digest": "e" * 64,
        "attestation":  {"mock": True, "measurement": "different"},
        "prev_hash":    "00" * 32,
    }
    assert set(mutations.keys()) == set(receipt_content_dict(BASELINE).keys())

    for field, new_value in mutations.items():
        mutated = dataclasses.replace(BASELINE, **{field: new_value})
        mh = receipt_content_hash(receipt_content_dict(mutated))
        assert mh != base_hash, f"hash did not change when {field} mutated"


def test_hash_unchanged_when_excluded_fields_mutated():
    base_hash = receipt_content_hash(receipt_content_dict(BASELINE))
    r2 = dataclasses.replace(BASELINE, this_hash="SOMETHING-ELSE", sig=b"OTHER-BYTES")
    assert receipt_content_hash(receipt_content_dict(r2)) == base_hash


def test_ticket_id_none_path():
    base_hash = receipt_content_hash(receipt_content_dict(BASELINE))
    rejected = dataclasses.replace(
        BASELINE,
        ticket_id=None,
        status="REJECTED",
        reason_code="OFF_MENU",
        result_digest=None,
        attestation=None,
    )
    rh = receipt_content_hash(receipt_content_dict(rejected))
    assert len(rh) == 64
    assert rh != base_hash
