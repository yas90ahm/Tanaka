"""On-device approval — a real dialog on your screen, not a terminal read.

This is the consumer gate's intended form: when the agent reaches for a
high-stakes action, a window pops up on YOUR machine — Allow once / Always
allow / Don't allow — like an OS permission prompt. The CLI approver (v0.4)
required a terminal; this one doesn't, which matters for the one place a
terminal prompt is structurally IMPOSSIBLE: Sentinel running as an MCP
server, where stdin/stdout ARE the JSON-RPC channel. There, an on-device
dialog is the only viable human gate.

FAIL CLOSED, both ways:
  - if showing the dialog raises (display died mid-session), the decision is
    DENY — the gate never fails open;
  - a closed window (the X button) is DENY;
  - a host with no display at all must not silently auto-deny forever and
    mint receipts that read as deliberate human choices — callers check
    `native_available()` up front and refuse to start confirm-mode instead
    (see `mcp_gateway --confirm`).

HONESTY: the dialog is a tkinter window (stdlib — the deps non-negotiable
holds). It is a real on-screen prompt, but it is NOT the OS vendor's
notification/consent API (UserNotifications, Windows toast), has no
biometric/secure-desktop binding, and a malicious local process could draw
over it. It demonstrates the on-device gate; a hardened consumer product
swaps `show_dialog` for the platform consent surface behind the same
approver contract.

The prompt CONTENT is built by a pure function (`build_prompt`) and the
verdict mapping is pure too, so both are exactly tested without a display;
the tkinter path itself runs under an env-gated test (SENTINEL_TEST_GUI=1).
"""

from dataclasses import dataclass

from sentinel_slice.consumer.approval import ApprovalDecision, CliApprover

# Verdicts a dialog can return. Anything else — None (window closed), an
# exception, garbage — maps to deny.
ALLOW_ONCE = "once"
ALLOW_ALWAYS = "always"
DENY = "deny"

# Button label -> verdict, in display order.
BUTTONS: tuple[tuple[str, str], ...] = (
    ("Allow once", ALLOW_ONCE),
    ("Always allow", ALLOW_ALWAYS),
    ("Don't allow", DENY),
)


@dataclass(frozen=True)
class PromptSpec:
    """Everything a dialog (any backend) needs to render one approval ask."""
    title: str
    heading: str
    lines: tuple[str, ...]


def build_prompt(order, capability) -> PromptSpec:
    """The on-screen content for one pending action. Pure."""
    return PromptSpec(
        title="Sentinel — approval needed",
        heading="Your agent wants to: {}".format(capability.name),
        lines=(
            "agent (principal): {}".format(order.principal),
            "capability: {}".format(capability.id),
            "risk: {} · side effects: {}".format(
                capability.risk_class, capability.side_effects),
            "on: {}".format(order.args),
        ),
    )


def decision_from_verdict(verdict) -> ApprovalDecision:
    """Map a dialog verdict to an ApprovalDecision. Unknown/None -> deny
    (fail closed). Pure."""
    if verdict == ALLOW_ONCE:
        return ApprovalDecision(allow=True, remember=False)
    if verdict == ALLOW_ALWAYS:
        return ApprovalDecision(allow=True, remember=True)
    return ApprovalDecision(allow=False, remember=False)


class NativeApprover:
    """Approver backed by an on-screen dialog. `show_fn(spec) -> verdict` is
    injectable so the mapping and the ConsumerLoop integration are exactly
    testable without a display; the default is the tkinter dialog."""

    def __init__(self, show_fn=None) -> None:
        self._show = show_fn if show_fn is not None else show_dialog
        self.prompts: list[PromptSpec] = []  # what was actually asked

    def decide(self, *, order, capability) -> ApprovalDecision:
        spec = build_prompt(order, capability)
        self.prompts.append(spec)
        try:
            verdict = self._show(spec)
        except Exception:
            # Display gone mid-session: the gate fails CLOSED, never open.
            return ApprovalDecision(allow=False, remember=False)
        return decision_from_verdict(verdict)


def native_available() -> bool:
    """True iff a tkinter dialog can actually be created here (display +
    tkinter present). Creates and destroys a withdrawn root to find out."""
    try:
        import tkinter
    except ImportError:
        return False
    try:
        root = tkinter.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:
        return False


def show_dialog(spec: PromptSpec, *, _test_autoclick: str | None = None) -> str | None:
    """Show the approval dialog, block until a choice, return its verdict
    (None if the window was closed — the caller maps that to deny).

    `_test_autoclick` exists ONLY for the env-gated GUI test: it schedules a
    real .invoke() on the named verdict's button so the genuine button path
    runs without a human. Production callers never pass it."""
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title(spec.title)
    root.attributes("-topmost", True)
    root.resizable(False, False)
    verdict: list[str | None] = [None]

    frame = ttk.Frame(root, padding=16)
    frame.grid(sticky="nsew")
    ttk.Label(frame, text=spec.heading, font=("", 11, "bold")).grid(
        sticky="w", pady=(0, 8))
    for line in spec.lines:
        ttk.Label(frame, text=line).grid(sticky="w")
    buttons = ttk.Frame(frame)
    buttons.grid(sticky="e", pady=(14, 0))

    def choose(value):
        def _set():
            verdict[0] = value
            root.destroy()
        return _set

    by_verdict = {}
    for col, (label, value) in enumerate(BUTTONS):
        btn = ttk.Button(buttons, text=label, command=choose(value))
        btn.grid(row=0, column=col, padx=(8, 0))
        by_verdict[value] = btn

    # Window closed without a choice -> verdict stays None -> deny.
    root.protocol("WM_DELETE_WINDOW", choose(None))
    root.bind("<Escape>", lambda _e: choose(None)())

    if _test_autoclick is not None:
        root.after(150, by_verdict[_test_autoclick].invoke)

    # Front and center: a background agent's prompt must not open buried.
    root.eval("tk::PlaceWindow . center")
    root.lift()
    root.focus_force()
    root.mainloop()
    return verdict[0]


def default_approver(input_fn=input, print_fn=print):
    """The best human gate available HERE: the on-device dialog when a
    display exists, else the CLI prompt (fine when a human owns the
    terminal — NOT fine inside an MCP server, which must check
    native_available() itself and refuse instead of falling back)."""
    if native_available():
        return NativeApprover()
    return CliApprover(input_fn=input_fn, print_fn=print_fn)
