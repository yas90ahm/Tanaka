"""Capability TEMPLATES — the no-code menu-building blocks.

A behavior is the code (a chef handler, shipped by engineers). A template is
the operator-facing description of that behavior: a plain-language label, what
it reads, what it produces, and sensible defaults. The operator builds a menu
item by picking a template and filling in a short form — no JSON, no code.

The `behavior` keys here MUST match chef_main._HANDLERS. That's the one
contract between "the code an engineer wrote" and "the menu an operator
curates." Adding a brand-new behavior is the only step that needs an engineer;
everything else (composing and tuning menu items) is point-and-fill.
"""

# behavior -> operator-facing template metadata + safe defaults.
TEMPLATES = {
    "draft_reply": {
        "label": "Draft a reply",
        "summary": "Read a message in a folder and write a draft reply for "
                   "review. Never sends.",
        "scoped_input": "thread_id",
        "inputs": {"thread_id": "string"},
        "outputs": {"draft": "text"},
        "side_effects": "none",
        "default_risk": "low",
        "default_requires_user_confirmation": False,
        "default_requires_second_admin": False,
        "default_recommended_max_rate": 20,
    },
    "docs_summarize": {
        "label": "Summarize a document",
        "summary": "Read a document in a folder and return a short extractive "
                   "summary (no AI model). Content never leaves the kitchen.",
        "scoped_input": "doc_id",
        "inputs": {"doc_id": "string"},
        "outputs": {"summary": "text"},
        "side_effects": "none",
        "default_risk": "low",
        "default_requires_user_confirmation": False,
        "default_requires_second_admin": False,
        "default_recommended_max_rate": 30,
    },
    "payment_request": {
        "label": "Request a payment",
        "summary": "Prepare a payment-authorization request for a human to "
                   "approve. HIGH RISK. Never moves money in this slice.",
        "scoped_input": "thread_id",
        "inputs": {"thread_id": "string"},
        "outputs": {"payment_request": "text"},
        "side_effects": "money_movement",
        "default_risk": "high",
        "default_requires_user_confirmation": True,
        "default_requires_second_admin": True,
        "default_recommended_max_rate": 2,
    },
}


def behaviors() -> list[str]:
    return sorted(TEMPLATES)


def template(behavior: str) -> dict | None:
    return TEMPLATES.get(behavior)
