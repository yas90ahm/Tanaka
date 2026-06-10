"""Menu catalog: a read-only registry of Capability objects loaded from
`sentinel_slice/capabilities/*.json`.

Structural blindness (Phase-3 contract §1): this module imports ONLY stdlib
and `sentinel_slice.spine.*`. It never imports kitchen and never reads,
opens, globs, or stats any fixture mailbox. The menu knows capabilities, not
mailboxes.
"""

import json
import os

from sentinel_slice.spine.types import Capability


# Absolute path to sentinel_slice/capabilities, computed from this file's
# location: catalog.py lives in sentinel_slice/menu/, capabilities is a
# sibling of menu/ under sentinel_slice/.
CAPABILITIES_DIR: str = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "capabilities")
)

# Where operator-created (no-code) capabilities are persisted. The menu builder
# writes here; humans never hand-edit it. Gitignored. Kept separate from the
# built-in capabilities so "shipped by engineers" vs "composed by the operator"
# stays legible.
CUSTOM_CAPABILITIES_DIR: str = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "capabilities_custom")
)


def _load_dir(directory: str) -> dict[str, Capability]:
    catalog: dict[str, Capability] = {}
    if not os.path.isdir(directory):
        return catalog
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(directory, name), "r", encoding="utf-8-sig") as fh:
            obj = json.load(fh)
        capability = Capability(**obj)
        catalog[capability.id] = capability
    return catalog


def load_catalog(
    capabilities_dir: str | None = None,
    *,
    custom_dir: str | None = None,
    include_disabled: bool = False,
) -> dict[str, Capability]:
    """Build the capability catalog, keyed by id. Read-only.

    Loads the built-in capabilities (capabilities_dir, default CAPABILITIES_DIR)
    plus, when `custom_dir` is given, operator-created ones (the no-code menu
    items). By default returns the ACTIVE MENU only — capabilities with
    enabled=False are excluded (ordering one is OFF_MENU). Pass
    include_disabled=True for the curation surface, which must show them.

    Built-in ids win over custom ids on collision (an operator can't shadow a
    shipped capability)."""
    directory = CAPABILITIES_DIR if capabilities_dir is None else capabilities_dir
    catalog: dict[str, Capability] = {}
    if custom_dir is not None:
        catalog.update(_load_dir(custom_dir))
    catalog.update(_load_dir(directory))  # built-ins override custom on clash
    if include_disabled:
        return catalog
    return {cid: cap for cid, cap in catalog.items() if cap.enabled}


def save_custom_capability(descriptor: dict, custom_dir: str | None = None) -> str:
    """Persist an operator-created capability descriptor as a JSON file (the
    builder produced it; no human edits JSON). Returns the file path. Refuses
    to shadow a built-in capability id."""
    target_dir = CUSTOM_CAPABILITIES_DIR if custom_dir is None else custom_dir
    cap_id = descriptor["id"]
    if cap_id in _load_dir(CAPABILITIES_DIR):
        raise ValueError("id {!r} is a built-in capability".format(cap_id))
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, cap_id + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(descriptor, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def set_custom_capability_enabled(
    capability_id: str, enabled: bool, custom_dir: str | None = None
) -> None:
    """Flip an operator capability on/off the active menu (rewrites its file's
    enabled flag). Only operator-created capabilities are toggleable here."""
    target_dir = CUSTOM_CAPABILITIES_DIR if custom_dir is None else custom_dir
    path = os.path.join(target_dir, capability_id + ".json")
    if not os.path.isfile(path):
        raise ValueError("no operator capability {!r}".format(capability_id))
    with open(path, "r", encoding="utf-8-sig") as fh:
        obj = json.load(fh)
    obj["enabled"] = bool(enabled)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def delete_custom_capability(capability_id: str, custom_dir: str | None = None) -> None:
    """Remove an operator-created capability entirely."""
    target_dir = CUSTOM_CAPABILITIES_DIR if custom_dir is None else custom_dir
    path = os.path.join(target_dir, capability_id + ".json")
    if not os.path.isfile(path):
        raise ValueError("no operator capability {!r}".format(capability_id))
    os.remove(path)


def get(
    capability_id: str,
    *,
    catalog: dict[str, Capability] | None = None,
) -> Capability | None:
    """Return the Capability for capability_id, or None if absent.
    If catalog is None, build one via load_catalog(). Never raises on an
    unknown id."""
    built = load_catalog() if catalog is None else catalog
    return built.get(capability_id)
