---
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
generated_by: osc-newfeature
type: feat
bulk_run: true
repo: NVIDIA/OpenShell
feature_complexity: M
Files:
  - proto/openshell.proto
  - proto/sandbox.proto
  - crates/openshell-core/src/grpc_client.rs
  - crates/openshell-core/src/settings.rs
  - crates/openshell-server/src/persistence/mod.rs
  - crates/openshell-server/src/persistence/sqlite.rs
  - crates/openshell-server/src/persistence/postgres.rs
  - crates/openshell-server/src/persistence/tests.rs
  - crates/openshell-server/src/grpc/mod.rs
  - crates/openshell-server/src/grpc/policy.rs
  - crates/openshell-server/src/grpc/sandbox.rs
  - crates/openshell-server/src/grpc/validation.rs
  - crates/openshell-server/src/auth/method_authz.rs
  - crates/openshell-server/src/auth/sandbox_methods.rs
  - crates/openshell-server/src/auth/authz.rs
  - crates/openshell-cli/src/main.rs
  - crates/openshell-cli/src/run.rs
  - crates/openshell-cli/src/policy_update.rs
  - crates/openshell-cli/src/completers.rs
  - crates/openshell-sandbox/src/lib.rs
  - crates/openshell-sandbox/src/sidecar_control.rs
  - crates/openshell-supervisor-network/data/sandbox-policy.rego
  - crates/openshell-supervisor-network/src/opa.rs
  - crates/openshell-supervisor-network/src/proxy.rs
  - crates/openshell-supervisor-network/src/run.rs
  - crates/openshell-ocsf/src/builders/network.rs
  - crates/openshell-ocsf/src/builders/config.rs
  - crates/openshell-tui/src/app.rs
  - crates/openshell-tui/src/lib.rs
  - crates/openshell-tui/src/ui/mod.rs
  - crates/openshell-tui/src/ui/sandbox_draft.rs
  - crates/openshell-tui/src/event.rs
  - python/openshell/sandbox.py
  - python/openshell/sandbox_test.py
  - python/openshell/_proto/__init__.py
  - e2e/python/test_sandbox_policy.py
  - e2e/rust/tests/live_policy_update.rs
  - docs/sandboxes/policies.mdx
  - docs/reference/policy-schema.mdx
  - docs/index.yml
  - architecture/security-policy.md
  - architecture/sandbox.md
  - architecture/gateway.md
---

# Time-boxed operator egress grants

Add a first-class, operator-issued allow that lets a running sandbox reach one host:port from named binaries for a bounded lifetime, without rewriting durable `network_policies` YAML.

## User-visible behavior

Operators issue, list, revoke, and optionally promote grants from the CLI:

```shell
openshell policy grant issue my-sandbox \
  --host api.example.com \
  --port 443 \
  --binary /usr/bin/curl \
  --ttl 30m

openshell policy grant list my-sandbox
openshell policy grant revoke my-sandbox --id <grant-id>
openshell policy grant promote my-sandbox --id <grant-id>
```

- `issue` creates an active grant. Default TTL is 30 minutes. Minimum TTL is 60 seconds. Maximum TTL is 24 hours. Repeat `--binary` to allow more than one path. Host patterns follow the existing first-label wildcard rules already enforced for policy endpoints (`*.example.com` is valid; `*` and TLD wildcards are rejected).
- While the grant is unexpired, CONNECT to that host:port from a matching binary succeeds even when durable `network_policies` have no matching allow. The proxy still applies hard blocks: SSRF / internal-address classification, trusted-gateway checks, TOFU binary identity, and seccomp/netns forcing traffic through the proxy.
- Grants are L4-only in this feature. They do not install REST/WebSocket/MCP rules. Inspected L7 endpoints already covered by durable policy are unchanged. `https://inference.local` stays on the inference interception path and does not consume a grant.
- When the TTL elapses, the next CONNECT to that destination is denied with reason `egress_grant_expired` if no durable rule matches, then `egress_grant_absent` after the grant row is gone. In-flight tunnels are not torn down at expiry; the next connection is.
- `list` prints grant id, host, port, binaries, remaining TTL, issuer principal, and whether the grant is active. Expired grants stay visible for 1 hour with status `expired`, then the gateway deletes them.
- `revoke` immediately removes the grant and bumps the sandbox config revision so the supervisor drops it on the next poll.
- `promote` copies the grant's host, port, and binaries into a durable `network_policies` merge using the existing `policy update` merge path, then revokes the grant. Promotion does not copy TTL. If a global policy is active for the sandbox, `promote` fails with a clear error, matching draft-approval behavior.
- Caps: 32 active grants per sandbox. A 33rd `issue` returns `FAILED_PRECONDITION`. Destroying a sandbox deletes its grants.
- TUI Network Rules pane shows an `Active grants` section above pending draft chunks: id, host:port, remaining TTL. Key `x` revokes the selected grant after a confirmation line. Grants are read-only in the policy YAML viewer.
- OCSF: issuing, revoking, expiring, and promoting emit `ConfigStateChange` (`Informational` on success). A CONNECT allowed only because of a grant emits `NetworkActivity` with action Allowed, disposition Allowed, firewall rule name `egress_grant`, and message `CONNECT granted <host>:<port> via egress grant`. Never log secrets.

Python `SandboxClient` grows `issue_egress_grant`, `list_egress_grants`, `revoke_egress_grant`, and `promote_egress_grant` that wrap the new RPCs.

## Implementation

Grants are not policy YAML. Persist them as object type `egress_grant` in the existing generic objects table (`crates/openshell-server/src/persistence/mod.rs`), scoped by sandbox id, with a protobuf payload `StoredEgressGrant` in `proto/openshell.proto`:

- `id`, `sandbox_id`, `host`, `port`, `binaries`, `expires_at_ms`, `issued_at_ms`, `issued_by`, `status`

Add RPCs on `OpenShell` in `proto/openshell.proto`:

- `IssueEgressGrant` / `ListEgressGrants` / `RevokeEgressGrant` / `PromoteEgressGrant`

Auth:

- Issue, revoke, promote: bearer, `config:write`, admin (same as `ApproveDraftChunk` and `UpdateConfig`).
- List: bearer, `config:read`, user (same as `GetDraftPolicy`).
- Sandbox JWTs must not call issue/revoke/promote. `GetSandboxConfig` remains sandbox-callable and is the delivery path.

`GetSandboxConfigResponse` in `proto/sandbox.proto` gains `repeated EgressGrant egress_grants = 9`. Including grants in the fingerprint so `config_revision` changes when grants change even if policy hash is unchanged.

Gateway handlers live in `crates/openshell-server/src/grpc/policy.rs` (new functions, wired from `crates/openshell-server/src/grpc/mod.rs`). Reuse host/port/binary validation in `crates/openshell-server/src/grpc/validation.rs` (same wildcard boundary as network endpoints). On issue, bump config revision. On sandbox delete in `crates/openshell-server/src/grpc/sandbox.rs`, delete grants by scope.

Supervisor poll in `crates/openshell-sandbox/src/lib.rs`:

- Extend `SettingsPollResult` in `crates/openshell-core/src/grpc_client.rs` with `egress_grants`.
- When grants change, push them into the proxy even if policy hash is unchanged. Do not skip this path in the "same revision" continue branch.
- Sidecar topology: add `GrantsUpdated` to `ControlUpdate` / `WireServerMessage` in `crates/openshell-sandbox/src/sidecar_control.rs` so the network sidecar receives the grant set.

Proxy enforcement in `crates/openshell-supervisor-network/src/proxy.rs`:

- Keep an `Arc<RwLock<Vec<ActiveEgressGrant>>>` on the proxy runtime (`crates/openshell-supervisor-network/src/run.rs`).
- After binary identity succeeds and after hard-block checks (internal address, trusted-gateway, invalid `allowed_ips`), if OPA would deny solely because no `network_policies` entry matches, consult grants. Match host (including the existing first-label wildcard semantics), port, and binary path (including cmdline/ancestor paths already used by OPA). Require `expires_at_ms > now`.
- If a grant matches, allow the CONNECT as L4 (raw or TLS passthrough per existing auto-detect). Do not synthesize L7 rules.
- Also inject `data.egress_grants` in `crates/openshell-supervisor-network/src/opa.rs` and add an `allow_network` clause in `crates/openshell-supervisor-network/data/sandbox-policy.rego` so OPA denials stay consistent with the proxy fallback. Proxy wall-clock check is authoritative for expiry between polls.

CLI:

- New `PolicyCommands::Grant` subcommand in `crates/openshell-cli/src/main.rs` with `Issue`, `List`, `Revoke`, `Promote`.
- Implementation in `crates/openshell-cli/src/run.rs`. Completions reuse `complete_sandbox_names` in `crates/openshell-cli/src/completers.rs`.
- `promote` calls the promote RPC (server-side merge), not a client-side YAML edit. Server uses the same merge helpers as `sandbox_policy_update` / `openshell_policy` (`crates/openshell-cli/src/policy_update.rs` stays the CLI planner; server merge already exists for draft approval).
- Add examples to `POLICY_EXAMPLES`.

TUI:

- `crates/openshell-tui/src/app.rs` stores `egress_grants`. Fetch via `ListEgressGrants` on the sandbox screen refresh used for drafts.
- Render in `crates/openshell-tui/src/ui/sandbox_draft.rs`. Wire keys in `handle_draft_key`. Spawn revoke in `crates/openshell-tui/src/lib.rs` like `spawn_draft_approve`.

Python SDK: methods on `SandboxClient` in `python/openshell/sandbox.py`.

Docs: operator workflow on `docs/sandboxes/policies.mdx`; grant object fields on `docs/reference/policy-schema.mdx`; architecture notes in `architecture/security-policy.md` (grants are not prover-gated policy proposals), `architecture/sandbox.md` (proxy consult order), `architecture/gateway.md` (new RPCs + object type). Navigation already lists those pages.

## Tests

- Persistence: put/list/delete by sandbox scope, unique id, 32-cap, delete-on-sandbox-delete (`crates/openshell-server/src/persistence/tests.rs`).
- Gateway: issue validation (wildcard reject, TTL bounds, binary required); list filters expired vs active; revoke bumps `config_revision`; promote merges a durable rule then deletes the grant; promote under global policy fails; sandbox principal cannot issue (`crates/openshell-server/src/grpc/policy.rs` tests, `crates/openshell-server/src/auth/sandbox_methods.rs`).
- OPA/proxy: CONNECT denied without grant; allowed with grant; denied after expiry; grant does not override internal-address block; grant does not skip binary identity (`crates/openshell-supervisor-network/src/opa.rs`, `crates/openshell-supervisor-network/src/proxy.rs`).
- Poll: grant-only config revision change reloads grants without a policy hash change (`crates/openshell-sandbox/src/lib.rs`).
- Sidecar: `GrantsUpdated` round-trip (`crates/openshell-sandbox/src/sidecar_control.rs`).
- CLI clap parse tests in `crates/openshell-cli/src/main.rs`.
- TUI key handling for revoke confirmation (`crates/openshell-tui/src/app.rs` tests).
- Python unit tests in `python/openshell/sandbox_test.py`.
- E2E: `e2e/python/test_sandbox_policy.py` — create sandbox with empty network policy, issue grant, CONNECT succeeds, revoke, CONNECT denied. `e2e/rust/tests/live_policy_update.rs` — promote then `policy get` shows the durable endpoint and grant list is empty.

## Risks

- Grants must not become a silent durable allow. Default TTL, hard max, and no auto-promote keep them ephemeral.
- A grant that matches a host whose resolved IP is internal must still fail the existing SSRF path; add an explicit regression test.
- Config poll currently continues early when `config_revision` is unchanged. Grant delivery depends on bumping that fingerprint; missing the bump leaves the proxy on a stale allow after revoke.
- Kubernetes sidecar topology will ignore grants unless `sidecar_control` carries them.
- Promotion under global policy would write sandbox-scoped YAML that operators never see in `GetSandboxConfig`; refuse it.
- In-flight tunnels outliving TTL is intentional; document it so operators do not assume cut-through.
- Do not log grant match against query strings or credential values.
