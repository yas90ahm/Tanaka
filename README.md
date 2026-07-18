# Tanaka

Tanaka is the repository. Sentinel Loop is the prototype inside it.

I built it around a rule I think should be obvious. An AI agent should not carry the credentials for every system it may use.

The agent asks for a named action from a fixed menu. A separate policy layer checks the request and issues a narrow ticket. The execution layer checks that ticket, then writes a signed receipt whether the request ran or was refused.

The restaurant names started as a way to keep those jobs straight. They stayed.

There is no language model in this repository. The test agent is deterministic because I am testing the control path.

## What works

- capability checks before execution
- policy decisions kept outside the agent
- signed tickets that are limited to one declared action
- a signed and hash-chained receipt ledger with a separate verifier
- a local operator console with policy authoring
- an MCP gateway with a consumer permission flow
- containment backends for the main desktop platforms, plus a KVM microVM path

The default execution path uses a subprocess contract. Stronger backends are optional, and the receipt records which one ran.

## What is unfinished

Hardware TEE attestation is mocked and says so in its output. SSO/OIDC federation is unfinished. The kitchen fixtures are cooperative test data.

This is a proof of concept. And I would not put it in front of a production system without an independent security review.

## Run it

Use Python 3.11 or newer.

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

The repository includes the public key needed to verify `ledger.db`. It does not include the matching private key. Generate your own pair before running a new instance:

```bash
python -m sentinel_slice.keygen
```

## What happens to an order

1. The agent asks for a capability. It has no service credential.
2. The policy layer checks the menu and the request scope.
3. An accepted request becomes a signed ticket.
4. The execution layer verifies the ticket before it runs anything.
5. The result comes back through a narrow return path.
6. The ledger records the decision without storing the result body.

## Operator tools

`sentinel-app` opens the desktop settings and activity view. It can connect supported MCP hosts and set Allow/Ask/Block preferences. The same view reads the receipt ledger.

`sentinel-console` manages the menu and local policy. Signed admin requests are supported. Directory federation is still only an integration seam.

`sentinel-mcp` starts the MCP gateway for a local host that can launch an MCP process. A website-only agent is outside this prototype's boundary.

## Capabilities

A capability is a menu item with a defined scope. A behaviour is the code that performs the work.

An operator can assemble capabilities from behaviour that has already been reviewed. Simple text-template behaviour can be authored without code. A new side effect, such as calling a payment API, still needs an engineer and a security review. I do not think a friendly form should hide that boundary.

## Containment

The repository includes subprocess isolation and platform-specific backends for Windows, Linux and macOS. There are also integration points for OCI/gVisor and KVM microVMs.

They do not provide the same guarantee. Check the containment field in the receipt and the platform test before making a claim about a run.

## Check it

```bash
python -m pytest
```

GitHub Actions runs the main suite and platform sandbox checks. The microVM workflow runs separately. Some GUI or VM checks skip on an ordinary development machine.

## Repository map

```text
sentinel_slice/       application and tests
microvm/              KVM root filesystem and helpers
docs/SPEC.md          original slice contract
docs/ARCHITECTURE.md  current code path and trust boundaries
docs/THREATS.md       threat boundary and known limits
docs/THESIS.md        the longer argument behind the design
ledger.db             deterministic demo ledger
```

## Packaging

`python build_installer.py` creates the current Windows ZIP installer. It is unsigned and has no automatic update path. Windows may warn about the unknown publisher.

Apache 2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
