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


def load_catalog(capabilities_dir: str | None = None) -> dict[str, Capability]:
    """Load every *.json file in capabilities_dir into a Capability via
    Capability(**obj). Key the returned dict by Capability.id. Read-only:
    opens files for reading only; no writes, no mutation after build.
    Default dir = CAPABILITIES_DIR."""
    directory = CAPABILITIES_DIR if capabilities_dir is None else capabilities_dir
    catalog: dict[str, Capability] = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        capability = Capability(**obj)
        catalog[capability.id] = capability
    return catalog


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
