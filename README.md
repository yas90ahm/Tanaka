# Tanaka

Sentinel Loop is the prototype inside this repository.

The agent should not hold the keys to the house. It asks for an action from a fixed menu, a separate cashier checks the request against policy, and a narrow signed ticket tells the execution layer exactly what it may do. Every result or refusal becomes a signed receipt.

That is the whole idea. The rest of the repository is an attempt to see whether the idea survives contact with an actual console, MCP, operating-system sandboxes and a ledger somebody else can verify.

There is no language model in the repository. The diner is a deterministic test agent because the governance path is the thing being tested.

## What is real

- capability and policy checks before execution
- signed, capability-bound tickets that the execution layer verifies
- an Ed25519-signed, hash-chained receipt ledger with a standalone verifier
- a local operator console and policy authoring
- an MCP gateway and consumer permission flow
- containment backends for Windows, Linux and macOS, plus a KVM microVM path

The default execution path remains a subprocess contract. Stronger backends are opt-in, and each receipt records the backend that ran.

Hardware TEE attestation is mocked. `MockAttestor` marks its output as mock. SSO/OIDC federation is also unfinished. The kitchen fixtures are cooperative test data, not a trusted external system.

This is a proof of concept, not a security product you should place in front of production systems without an independent review.

## Run the slice

Python 3.11 or newer is required.

```bash
git clone https://github.com/yas90ahm/Tanaka.git
cd Tanaka
python -m venv .venv
```

Activate the environment:

```bash
# Linux or macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install the project and test tools:

```bash
pip install -e ".[dev]"
```

Verify the committed demo ledger:

```bash
python sentinel_slice/verify_ledger.py ledger.db sentinel_slice/keys/cashier_ed25519_public.pem
```

Run one allowed order and one blocked prompt-injection attempt:

```bash
python -m sentinel_slice.run_slice demo-ledger.db
```

Then verify the new ledger with the public key that matches the signing key used for that run.

The repository ships a demo public key so the committed `ledger.db` can be verified. It never ships the matching private key. Generate your own keypair before running your own instance:

```bash
python -m sentinel_slice.keygen
```

## The path of an order

1. The diner asks for a named capability. It has no service credentials.
2. The cashier checks the menu, policy, scope, nonce, rate and kill switch.
3. An accepted request becomes a signed ticket.
4. The chef verifies the ticket and runs only the declared behavior.
5. The window returns the result.
6. The ledger records what happened, including refusals, without storing the result body.

The takeout names are a metaphor. In code they are ordinary modules with narrow jobs, which is the point.

## Operator surfaces

### Desktop app

`sentinel-app` opens the local desktop shell. It can connect supported MCP hosts, set Allow/Ask/Block preferences and show activity from the receipt ledger.

```bash
sentinel-app
```

The app is a settings and activity surface. It is not an auto-updating, code-signed desktop product.

### Console

The local console manages the menu, policy and review views:

```bash
sentinel-console
```

The current console uses signed admin requests. Directory federation remains a seam, not a completed feature.

### MCP gateway

Any local host that can start an MCP process and send the order shape can use the gateway:

```bash
sentinel-mcp
```

Website-only agents with no local process are outside this prototype's boundary.

## Capabilities and behaviors

A capability is a menu item with scope and care settings. A behavior is the code that performs the work.

An operator can compose capabilities from behaviors already reviewed. Simple text-template behavior can also be authored without code. A genuinely new side effect, such as calling an external payment API, still needs an engineer and a security review. I do not think a friendly form should make that boundary disappear.

## Containment backends

The repository includes:

- subprocess isolation for the basic contract
- Windows AppContainer
- Linux seccomp and Landlock
- macOS Seatbelt
- OCI/gVisor integration points
- KVM microVM support

These do not provide identical guarantees. Read the receipt's containment field and the platform-specific tests before making a claim about a run.

## Tests

```bash
python -m pytest
```

GitHub Actions runs the main test matrix, platform sandbox checks and the microVM workflow. Some platform, GUI and VM checks skip on a normal local machine. Test totals are intentionally not written here because they change; the current workflow is the source of truth.

## Other commands

Installing the package adds:

```text
sentinel-init            first-run setup
sentinel-keygen          create a local signing keypair
sentinel-run             run the slice
sentinel-verify          verify a receipt ledger
sentinel-verify-policy   verify policy history
sentinel-gateway         run the agent gateway
sentinel-inspect         render an operator-readable report
sentinel-drill           run the fixed adversarial curriculum
sentinel-console         start the local console
sentinel-mcp             start the MCP gateway
sentinel-policy-form     open policy authoring
```

## Repository map

```text
sentinel_slice/          application and tests
microvm/                KVM rootfs and helpers
docs/SPEC.md             original slice contract
docs/ARCHITECTURE.md     current code path and trust boundaries
docs/THREATS.md          threat boundary and known limits
docs/THESIS.md           the longer argument behind the design
docs/history/            earlier architecture, console and build records
ledger.db                committed deterministic demo ledger
```

## Packaging

`python build_installer.py` builds the current Windows ZIP installer. It is unsigned and has no auto-update path. Windows may warn about the unknown publisher. A real release would need code signing and a supported installer format.

## License

Apache 2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
