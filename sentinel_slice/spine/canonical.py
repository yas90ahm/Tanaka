# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
import json


def canonical_bytes(obj) -> bytes:
    """Return the canonical JSON encoding of `obj` as UTF-8 bytes.

    Canonical form: json.dumps(obj, sort_keys=True, separators=(",", ":"))
    encoded to UTF-8. This is the ONLY serialization used for hashing and
    signing anywhere in the slice.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
