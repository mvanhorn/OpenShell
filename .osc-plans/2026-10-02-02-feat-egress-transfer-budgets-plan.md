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
  - crates/openshell-core/src/settings.rs
  - crates/openshell-core/src/activity.rs
  - crates/openshell-core/src/grpc_client.rs
  - crates/openshell-core/src/telemetry.rs
  - crates/openshell-server/src/grpc/mod.rs
  - crates/openshell-server/src/grpc/policy.rs
  - crates/openshell-server/src/grpc/sandbox.rs
  - crates/openshell-server/src/telemetry.rs
  - crates/openshell-sandbox/src/lib.rs
  - crates/openshell-sandbox/src/activity_aggregator.rs
  - crates/openshell-supervisor-network/src/proxy.rs
  - crates/openshell-supervisor-network/src/run.rs
  - crates/openshell-supervisor-network/src/l7/relay.rs
  - crates/openshell-supervisor-network/src/l7/http.rs
  - crates/openshell-supervisor-network/src/l7/rest.rs
  - crates/openshell-ocsf/src/builders/network.rs
  - crates/openshell-cli/src/main.rs
  - crates/openshell-cli/src/run.rs
  - crates/openshell-tui/src/app.rs
  - crates/openshell-tui/src/ui/sandbox_detail.rs
  - crates/openshell-tui/src/ui/sandbox_settings.rs
  - crates/openshell-tui/src/ui/sandboxes.rs
  - e2e/rust/tests/settings_management.rs
  - e2e/python/test_sandbox_policy.py
  - docs/sandboxes/policies.mdx
  - docs/sandboxes/manage-sandboxes.mdx
  - docs/observability/logging.mdx
  - docs/reference/policy-schema.mdx
  - architecture/sandbox.md
  - architecture/security-policy.md
  - architecture/gateway.md
---

# Per-sandbox egress transfer budgets

Add operator-configured byte and connection budgets that the sandbox proxy enforces on ordinary egress, so an allowed destination cannot move unbounded data for the life of the sandbox.

## User-visible behavior

Two registered runtime settings, default unlimited (`0`):

| Key | Kind | Default | Meaning |
|---|---|---|---|
| `egress_budget_bytes` | int | `0` | Max payload bytes the proxy forwards for the sandbox lifetime. `0` disables the cap. |
| `egress_budget_connections` | int | `0` | Max successful CONNECT/FORWARD tunnels the proxy opens for the sandbox lifetime. `0` disables the cap. |

Set them with the existing settings CLI:

```shell
openshell settings set my-sandbox --key egress_budget_bytes --value 104857600
openshell settings set my-sandbox --key egress_budget_connections --value 500
openshell settings set --global --key egress_budget_bytes --value 1073741824
```

Gateway scope wins over sandbox scope, matching `proposal_approval_mode`. Negative values are rejected at `UpdateConfig` / `settings set` with `INVALID_ARGUMENT`.

Enforcement:

- The proxy counts bytes copied in either direction on allowed tunnels (CONNECT raw, CONNECT L7, HTTP FORWARD). Count after the policy allow, including TLS handshake ciphertext on inspected tunnels.
- `https://inference.local` is excluded from both counters. Ordinary policy-allowed inference hosts (non-`inference.local`) are included.
- When either cap is finite and the next CONNECT or FORWARD would exceed it, the proxy denies with HTTP `403`, deny group `egress_budget`, and reason `egress_budget_bytes` or `egress_budget_connections`. OCSF `NetworkActivity` uses action Denied, disposition Blocked, severity Medium, message `CONNECT denied <host>:<port> egress budget exceeded`.
- An in-flight tunnel that crosses the byte cap is closed after the current copy chunk; the deny is logged once. New CONNECTs stay denied until the sandbox is destroyed and recreated. Changing a setting to a higher cap unblocks new CONNECTs without resetting counters. Setting a cap to `0` disables enforcement but does not wipe usage. Lowering a cap below current usage denies the next CONNECT immediately.
- Counters reset only when the supervisor process starts (new sandbox or supervisor restart). They do not reset on policy reload.

Read usage:

- `openshell sandbox get my-sandbox` prints `egress_bytes_forwarded`, `egress_connections_opened`, and the effective caps (or `unlimited`).
- JSON/YAML output includes an `egress_budget` object on sandbox status.
- TUI sandbox metadata pane shows `egress 12.4 MiB / 100 MiB · 41 / 500 conn`. When unlimited, show usage only.

Denied connections still increment the existing anonymous denial counters (`denied_action_count`, group `egress_budget`) flushed through `SubmitPolicyAnalysis`.

## Implementation

Settings registry in `crates/openshell-core/src/settings.rs`:

- Add `EGRESS_BUDGET_BYTES_KEY` and `EGRESS_BUDGET_CONNECTIONS_KEY` as `SettingValueKind::Int`.
- Document in the module comment's add-a-setting checklist. Tests in that file cover lookup, kind, and `setting_for_key`.
- Server already rejects unknown keys and type mismatches in `crates/openshell-server/src/grpc/policy.rs` (`proto_setting_to_stored`). Add tests that accept `0` and positive ints and reject negatives / non-integers.

Proxy counters in `crates/openshell-supervisor-network/src/run.rs`:

- `EgressBudget` struct with `AtomicU64` bytes, `AtomicU64` connections, `AtomicU64` byte_cap, `AtomicU64` conn_cap (`0` = unlimited).
- Share via `Arc` with the CONNECT/FORWARD handlers in `crates/openshell-supervisor-network/src/proxy.rs`.

Byte accounting:

- Replace `tokio::io::copy_bidirectional` call sites in `proxy.rs` (raw CONNECT, TLS-without-L7) with a counting wrapper that saturating-adds copied bytes onto the budget and returns `BudgetExceeded` when a finite cap is crossed mid-stream.
- L7 paths in `crates/openshell-supervisor-network/src/l7/relay.rs`, `http.rs`, and `rest.rs` must count request+response body bytes (and CONNECT boilerplate) through the same wrapper. Do not count inference.local relays.
- Before opening a new upstream, check `connections_opened + 1` against `egress_budget_connections`. Increment only after the CONNECT is allowed by policy and hard-block checks. Budget denials happen after SSRF/internal-address denials so those reasons stay primary.

Settings application:

- Supervisor poll in `crates/openshell-sandbox/src/lib.rs` already extracts settings on each `GetSandboxConfig`. Read the two int keys (gateway-resolved effective values are already in `SettingsPollResult.settings`) and push caps into the proxy `EgressBudget` atomics. Apply even when policy hash is unchanged.
- Missing keys mean unlimited.

Usage reporting:

- Extend `ActivityEvent` in `crates/openshell-core/src/activity.rs` with `bytes_forwarded: u64` (zero for deny-only events) **or** add a dedicated `try_record_budget` that the proxy calls with delta bytes. Prefer extending `FlushableActivitySummary` in `crates/openshell-sandbox/src/activity_aggregator.rs` with lifetime-or-window byte totals.
- Extend `NetworkActivitySummary` in `proto/openshell.proto` with `bytes_forwarded` and `connections_opened`. `flush_activity_to_gateway` in `crates/openshell-sandbox/src/lib.rs` fills them. Gateway `crates/openshell-server/src/telemetry.rs` accumulates per-sandbox totals.
- Add `EgressBudgetStatus` to `SandboxStatus` in `proto/openshell.proto`: `bytes_forwarded`, `connections_opened`, `bytes_limit`, `connections_limit` (`0` limit means unlimited). `handle_get_sandbox` in `crates/openshell-server/src/grpc/sandbox.rs` copies the telemetry snapshot plus effective settings.

CLI:

- `crates/openshell-cli/src/run.rs` `sandbox_get` table output grows the three usage lines. Settings examples in `crates/openshell-cli/src/main.rs` include one budget `settings set`.
- Existing `settings set` / `settings get` work once the keys are registered; no new subcommand required. `crates/openshell-cli/src/run.rs` parse tests for int settings already exist nearby — add budget keys.

TUI:

- `crates/openshell-tui/src/ui/sandbox_detail.rs` and list cells in `crates/openshell-tui/src/ui/sandboxes.rs` show compact usage.
- Settings tab in `crates/openshell-tui/src/ui/sandbox_settings.rs` lists the new keys automatically from `GetSandboxConfig`.

Docs: operator section on `docs/sandboxes/policies.mdx` and a status field note on `docs/sandboxes/manage-sandboxes.mdx`. Mention the `egress_budget` deny group on `docs/observability/logging.mdx`. Architecture: enforcement in `architecture/sandbox.md` and `architecture/security-policy.md`; status field in `architecture/gateway.md`. These settings are not gateway TOML — do not change `docs/reference/gateway-config.mdx`.

## Tests

- Settings registry unit tests (`crates/openshell-core/src/settings.rs`).
- Gateway `UpdateConfig` rejects negative budgets; `GetSandbox` includes zeros when unset (`crates/openshell-server/src/grpc/policy.rs`).
- Proxy: unlimited allows; byte cap denies the CONNECT after the cap; connection cap denies the N+1 tunnel; inference.local excluded; lowering the cap below usage denies the next CONNECT; raising the cap allows again without reset (`crates/openshell-supervisor-network/src/proxy.rs`).
- Counting wrapper unit tests next to the helper (same file or `proxy.rs` tests module).
- Aggregator flush includes byte totals (`crates/openshell-sandbox/src/activity_aggregator.rs`).
- CLI `settings set` parse for the new keys (`crates/openshell-cli/src/run.rs`).
- E2E `e2e/rust/tests/settings_management.rs`: set `egress_budget_bytes` on a sandbox, `settings get` shows it, global override blocks sandbox write.
- E2E `e2e/python/test_sandbox_policy.py`: sandbox with a tiny `egress_budget_connections=1`, first CONNECT to an allowed host succeeds, second CONNECT is denied with budget in the body/logs.

## Risks

- Byte counts on TLS-inspected tunnels include ciphertext and HTTP framing, so operators comparing against application payload size will see a higher number. Document that the cap is proxy-forwarded bytes, not decoded application bytes.
- `copy_bidirectional` does not report per-stream totals today; a buggy wrapper that counts twice (CONNECT preamble plus L7 relay) would trip caps early. One counter increment path per tunnel.
- Activity flush is anonymous and periodic (10s). Status shown by `sandbox get` can lag enforcement by one flush interval. CLI copy should say "reported usage" not "live proxy register".
- A global byte cap of a small value can deny every sandbox at once. Keep default `0`. Global-set confirmation already exists (`--yes`).
- Do not put payload snippets in OCSF or denial samples when the deny reason is budget; existing L7 samples must stay disabled on this path.
- Sidecar topology: budget state lives in the network sidecar's proxy process. Settings poll already runs where the proxy runs; do not duplicate counters in the process supervisor.
