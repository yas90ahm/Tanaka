# Current architecture

Tanaka is the repository. Sentinel Loop is the working prototype inside it.

The boundary is simple: an agent can ask for an action, but it does not carry
the signing key or service credentials. A separate path decides whether the
request is allowed. If it is, the execution layer receives a narrow, signed
ticket rather than the agent's authority. The current ticket records when it
was issued but does not enforce an expiry.

## One order, end to end

1. A caller creates an `Order` for a named capability. The command-line and
   MCP gateways translate their input into this same type.
2. `cashier.engine.evaluate_order` checks the nonce, menu, role, kill switch,
   scope and rate limit. It is read-only, which lets the console simulate a
   policy without spending a nonce or writing a receipt.
3. `cashier.engine.process_order` owns the side effects. It consumes the nonce,
   records a rejection or signs a capability-bound `Ticket` for an accepted
   order.
4. `chef.runner.run_chef` verifies and executes the ticket through a selected
   `Sandbox`. The default is a subprocess. Platform and microVM backends are
   available, but they do not all make the same containment promise.
5. The result goes to the serving window. Its contents do not go into the
   ledger.
6. `ledger.receipts.Ledger` appends a signed, hash-chained receipt. A fulfilled
   receipt contains a digest of the result and the containment class. A refusal
   is recorded too.

`loop.SentinelLoop` wires these pieces together and is the reference path used
by the demo and tests.

## The trust boundaries

- The cashier holds the private signing key. The diner and gateways do not.
- The cashier makes decisions from order metadata, capability definitions and
  policy. It does not read the fixture content.
- The chef receives the signed ticket and narrowed arguments. Its temporary
  workspace is removed after each run.
- The serving window holds output content. The ledger holds metadata and a
  digest, not the output body.
- `verify_ledger.py` and `verify_policy_history.py` are standalone verifiers.
  They deliberately do not import the application package.

The committed attestor is a mock and labels itself as one. The default
subprocess path proves an execution contract, not a hardware isolation
guarantee. See [THREATS.md](THREATS.md) before making a stronger claim.

## Other paths through the same core

- `mcp_gateway.py` exposes capabilities as local MCP tools.
- `consumer/loop.py` adds Allow, Ask or Block before an accepted ticket runs.
- `console/` manages capabilities and policy through a localhost service with
  signed admin requests.
- `curriculum/drill.py` sends a fixed adversarial probe set through the real
  order path.
- `inspector.py` validates the chain before producing an operator-readable
  report.

These are different entry points. They should not become separate versions of
the authorization rules.

## Repository map

```text
sentinel_slice/spine/       shared order, ticket and receipt types
sentinel_slice/menu/        capability catalogue
sentinel_slice/cashier/     policy decision, nonce/rate state and ticket signing
sentinel_slice/chef/        ticket execution and containment backends
sentinel_slice/window/      result handoff
sentinel_slice/ledger/      append-only signed receipt chain
sentinel_slice/consumer/    personal Allow/Ask/Block gate
sentinel_slice/console/     local policy and review surface
sentinel_slice/tests/       unit, acceptance and platform-gated tests
microvm/                    KVM root filesystem and helpers
docs/history/               earlier plans and build records
```

The original v0.1 contract remains in [SPEC.md](SPEC.md). The longer argument
behind the design is in [THESIS.md](THESIS.md).
