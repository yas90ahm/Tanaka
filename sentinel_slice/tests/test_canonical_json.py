# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
import pytest

from sentinel_slice.spine.canonical import canonical_bytes


def test_canonical_bytes_stable_across_key_order():
    a = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    d = {}
    d["c"] = {}
    d["c"]["x"] = 10
    d["c"]["y"] = 20
    d["a"] = 1
    d["b"] = 2
    assert canonical_bytes(a) == canonical_bytes(d)


def test_canonical_bytes_exact_literal():
    obj = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    assert canonical_bytes(obj) == b'{"a":1,"b":2,"c":{"x":10,"y":20}}'


def test_canonical_bytes_returns_bytes():
    assert canonical_bytes({"x": 1}) == b'{"x":1}'
    assert isinstance(canonical_bytes({"x": 1}), bytes)


def test_canonical_bytes_rejects_bytes_value():
    with pytest.raises(TypeError):
        canonical_bytes({"sig": b"\x00\x01"})


def test_canonical_bytes_null_and_bool():
    # Canonical form sorts keys (a,b,c) and preserves each key's own value:
    # a=None->null, b=True->true, c=False->false. The contract draft (§5.5)
    # printed b'{"a":null,"b":false,"c":true}', which transposes the b/c
    # VALUES and contradicts its own mandated json.dumps(...sort_keys=True...).
    # A test asserting that draft literal would only pass against a broken
    # encoder, so this asserts the real canonical output instead.
    assert canonical_bytes({"a": None, "b": True, "c": False}) == b'{"a":null,"b":true,"c":false}'
