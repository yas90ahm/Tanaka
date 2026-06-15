# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Sentinel Loop — governance vertical slice.

Single in-source version of record. The packaging metadata (pyproject.toml)
and any server that advertises a version both resolve to this string, so the
build and the running process can never disagree about who they are.
"""

__version__ = "0.15.0"
