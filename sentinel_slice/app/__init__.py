# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""The door — the consumer-facing shell.

Everything a non-technical person touches: connecting Sentinel to their AI
(an MCP host), setting Allow/Ask/Block permissions, and seeing what their
agent did. The valuable, testable logic lives in `connect.py` (wiring MCP
hosts) and `firstrun.py` (readiness); `shell.py` is a thin tkinter view over
them.
"""
