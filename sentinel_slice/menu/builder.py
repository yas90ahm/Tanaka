"""No-code capability builder.

Turns a short, plain-language form into a valid capability descriptor — the
operator never writes JSON. They pick a template (behavior) and provide a
name, an id slug, a description, the folder/namespace it applies to, the risk
friction, and a rate. Everything technical (inputs/outputs/scoped_input) comes
from the template.

`build_descriptor` is pure and validated; persistence lives in the catalog
(save_custom_capability). Adding a brand-new behavior still needs an engineer
(a chef handler) — that's the only irreducibly technical step.
"""

import re

from sentinel_slice.menu.templates import template

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")


class CapabilityBuildError(ValueError):
    pass


def build_descriptor(
    *,
    behavior: str,
    capability_id: str,
    name: str,
    description: str = "",
    risk_class: str | None = None,
    recommended_max_rate: int | None = None,
    requires_user_confirmation: bool | None = None,
    requires_second_admin: bool | None = None,
    enabled: bool = True,
) -> dict:
    """Build a capability descriptor dict from form fields + a template.

    Technical fields (inputs/outputs/scoped_input/side_effects) are taken from
    the template; risk/friction default from the template but can be tightened
    by the operator. Raises CapabilityBuildError on anything invalid."""
    tmpl = template(behavior)
    if tmpl is None:
        raise CapabilityBuildError(
            "unknown behavior {!r}; pick one of the available templates".format(
                behavior))
    if not isinstance(capability_id, str) or not _ID_RE.match(capability_id):
        raise CapabilityBuildError(
            "capability id must be lowercase letters/digits/._- (3-80 chars)")
    if not isinstance(name, str) or not name.strip():
        raise CapabilityBuildError("a name is required")

    risk = risk_class if risk_class is not None else tmpl["default_risk"]
    if risk not in ("low", "medium", "high"):
        raise CapabilityBuildError("risk must be low, medium, or high")

    def _flag(value, default):
        return default if value is None else bool(value)

    rate = (recommended_max_rate if recommended_max_rate is not None
            else tmpl["default_recommended_max_rate"])
    if not isinstance(rate, int) or isinstance(rate, bool) or rate < 0:
        raise CapabilityBuildError("recommended_max_rate must be a non-negative int")

    return {
        "id": capability_id,
        "name": name.strip(),
        "behavior": behavior,
        "inputs": dict(tmpl["inputs"]),
        "outputs": dict(tmpl["outputs"]),
        "side_effects": tmpl["side_effects"],
        "scope": "own_queue",
        "scoped_input": tmpl["scoped_input"],
        "risk_class": risk,
        "description": description.strip(),
        "recommended_max_rate": rate,
        "requires_user_confirmation": _flag(
            requires_user_confirmation, tmpl["default_requires_user_confirmation"]),
        "requires_second_admin": _flag(
            requires_second_admin, tmpl["default_requires_second_admin"]),
        "enabled": bool(enabled),
    }
