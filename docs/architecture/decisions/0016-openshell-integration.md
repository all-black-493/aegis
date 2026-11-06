# ADR-0016: OpenShell integration

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Phase 3 makes NVIDIA OpenShell the runtime enforcement boundary for AEGIS workloads (AGENTS.md §3.3). AEGIS must drive OpenShell without replacing it, depend on a verified release rather than on its documentation alone, and never run anything outside a sandbox when OpenShell is unavailable.

This ADR covers Phase 3 Increment 1:

- the runtime contract;
- the OpenShell adapter;
- configuration;
- the doctor check;
- the behaviour of OpenShell 0.1.6 as verified on the development host.

AEGIS policies, the prover gate and the enforcement probes follow in later increments.

## Version verified

| Item | Finding |
|---|---|
| Package | NVIDIA's Debian package `openshell 0.1.6-1` (Apache-2.0), released 2026-10-27. It installs `/usr/bin/openshell`, `/usr/bin/openshell-gateway` and `/usr/bin/openshell-prover`. The documentation is the `v0.1.6` tag, commit `ac7f615` |
| Gateway | `openshell-gateway.service`, a user systemd unit, on `https://127.0.0.1:17670` with mTLS. It uses the `docker` compute driver (Docker 28.3.2, cgroup v2). Images are `ghcr.io/nvidia/openshell/{supervisor,sandbox}:0.1.6` |
| Identity | The CLI authenticates as `openshell-client` (role `openshell-user`). A local gateway without OIDC roles treats every authenticated user as a Platform Admin |
| Host | Linux 7.0, Landlock ABI 8 (OpenShell needs at least 3), seccomp and AppArmor active |

## Behaviour observed on 2026-11-02

| Area | Observed |
|---|---|
| Workspaces | Created only by a Platform Admin (`openshell workspace create --name …`). The CLI scopes everything with `--workspace`. Sandbox containers are named `openshell-<workspace>--<name>-<id>`, with a separate supervisor container. `workspace get` has no `--output` flag |
| Creating | `sandbox create --name N --from IMAGE --policy FILE --cpu --memory --label k=v --no-tty --detach --no-auto-providers --output json -- CMD` returned in under a second with the local `ubuntu:24.04`. The pull policy is `if_not_present`. The JSON includes `phase` (`Ready`), `configuration_admission.state` (`accepted`) and its `policy_hash`, `labels`, `workspace` and `id`. A missing policy file fails the command |
| Identity inside | `run_as_user`/`run_as_group` `1000` ran the workload as UID 1000. Its supplementary groups come from the image's `/etc/group` (`ubuntu` is in `sudo` and `adm`) |
| Filesystem | With `compatibility: hard_requirement`, a path outside the policy was refused even when its owner was the workload's UID: reads and writes under `/home/ubuntu` (owner `ubuntu`, mode 750) failed with `EACCES`. Writes under read-only `/usr` and `/etc` also failed, but there Unix permissions already refuse them, so only user-owned paths show Landlock itself |
| Network, no rules | No proxy variables and no routes; `connect()` fails with `EACCES` |
| Network, one rule | Connections are brokered transparently: there is still no proxy variable, and the supervisor makes the connection from the host. An IPv4 literal on the Docker bridge (`172.17.0.1`) worked as an exact host. The allowed `bash` connection reached a canary on that port. The same host on another port, `1.1.1.1:443`, and `perl` to the allowed endpoint all failed with `EACCES`, and the canary saw none of them |
| Sandbox names | At most 19 characters; a longer name is refused with `name exceeds maximum length`. AEGIS's names are `aegis-` plus 1–13 characters (ADR-0018) |
| Image IDs | `--from sha256:<image ID>` works with the Docker driver, and the workload container runs exactly that image (ADR-0017) |
| Denial records | Only for a sandbox with at least one network rule: in a sandbox with none, a refused connection leaves no log record. `openshell logs NAME --source sandbox` shows a proxy warning and an OCSF line per denial, for example `NET:OPEN [MED] DENIED /usr/bin/perl(0) -> 172.17.0.1:18901 [reason:transparent_tcp_policy_denied]`. The log also records `Isolation boundary enforcement confirmed backend=openshell-sandbox`, and the loaded revision's hash matches `policy_hash` |
| Effective policy | With a network rule, the effective policy gained the baseline path `/var/log` (read-only) as revision 2 (`loaded`); revision 1 became `superseded`. `sandbox get N --policy-only` prints the effective policy |
| Exec | `sandbox exec --name N --no-tty --no-login-shell --timeout T -- ARGV` returns the command's exit status, and 124 when `--timeout` expires. A missing sandbox exits 1 with `sandbox not found` on stderr |
| Deleting | `sandbox delete N` returns `deletion accepted; cleanup is pending`. Both containers were gone within a second. Deleting again is a no-op exiting 0, and `sandbox get` then exits 1 with `not found` |
| Status | `status --output json` reports `status` (`connected`) and `version`. An unknown gateway name also **exits 0**, with `{"status": "not_configured"}` |
| Errors | The CLI prints errors as `Error: × code: …, message: "…"` and wraps them at 80 columns inside a `│` border, so a message can be split across lines |
| Prover | `openshell-prover check C --boundary B --output json` reports `schema_version` 1, `prover_version`, `coverage.domains` (`filesystem`, `network_l4`, `network_rest`, `process`, `landlock`), `result`, `exit_code`, `counterexample`, `reason_code` and `reason`. The effective policy against its boundary gave `within_boundary` (0). Landlock widened to `best_effort` gave `exceeds_boundary` (1, counterexample `landlock`), and so did an extra port. A sub-path of a boundary path, and a different UID, gave `unsupported` (3) |
| Global policy | None is active. `policy get --global` exits 1 with `no global policy revision found` |

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Contract | `aegis.runtime.contract` defines `SandboxSpec`, `Sandbox`, `ExecResult`, `RuntimeStatus` and `ProverVerdict`. Its errors are `RuntimeUnavailableError` (retryable), `RuntimeRefusedError` and `RuntimeProtocolError`, each with a short `code`. The `SandboxRuntime` protocol has `check`, `create`, `get`, `exec`, `effective_policy`, `delete`, `managed` and `check_policy`. Nothing in AEGIS's domain imports OpenShell (layering rules) | The worker will depend on the contract, as it does for model providers (ADR-0013). |
| Adapter | `aegis.integrations.openshell` drives the CLI and the prover as subprocesses. The binaries are fixed at `/usr/bin/openshell` and `/usr/bin/openshell-prover`, and no setting can name another. JSON output is used wherever 0.1.6 has it. There is no new dependency (decision U2) | The CLI is the documented interface. The Python SDK would add gRPC dependencies. |
| Allow-list | Only `status`, `workspace get/create`, `sandbox create/get/list/exec/delete`, `policy get` and `logs` (added for the enforcement records of ADR-0018), plus `--version` and `openshell-prover check`. Every command carries `--gateway`, `--workspace` and `--color never`. Policy changes on live sandboxes, global policies, providers, services, forwards, templates and settings are not reachable | The adapter can only do what Phase 3 needs. |
| Environment | The CLI receives only `PATH=/usr/bin:/bin`, `LANG`, `NO_COLOR`, `HOME` and `XDG_CONFIG_HOME` when it is absolute. No AEGIS variable and no `OPENSHELL_*` override (such as `OPENSHELL_GATEWAY_INSECURE`) reaches it. Each call runs in its own session, with stdout and stderr capped and a timeout that kills the process group | No secret leaves AEGIS, nothing in the environment can weaken TLS, and a misbehaving CLI cannot exhaust the worker. |
| Version pin | The CLI, prover and gateway must report exactly 0.1.6, checked before every `create` and every prover run. Anything else is refused with `version_mismatch`. The status must be `connected`, never inferred from the exit code (decision U8) | An upgrade between tasks is noticed before it runs anything. |
| Isolation on a shared gateway | AEGIS uses its own workspace (`AEGIS_OPENSHELL_WORKSPACE`, default `aegis`; `default` is refused), created only by `aegis openshell init` (`make openshell-init`). Sandboxes are named `aegis-[a-z0-9-]` and labelled `aegis.managed=true`. `managed()` filters by both, on top of the gateway's selector. `delete()` refuses any other name. A global policy makes `check()` fail (decision U1) | AEGIS can only list and delete its own sandboxes. A workspace is a scope, not an access boundary, because the CLI identity is a Platform Admin. |
| Creating | `create()` adds `--detach --no-tty --no-auto-providers` and runs `/usr/bin/sleep infinity` as the main process. It requires `phase` `Ready` and admission `accepted`; otherwise it deletes the sandbox and raises `sandbox_rejected` or `sandbox_not_ready` | A sandbox is either fully admitted or gone. |
| Exec | Arguments are an absolute program plus at most 64 arguments of up to 4 KiB, with no NUL, and a timeout of 1–300 s. Output is capped at 64 KiB per stream and marked truncated. `exec()` first requires the sandbox to be `Ready`, because a missing sandbox and a failing command both exit 1. Exit 124 at or after the timeout is reported as `timed_out` | The caller can tell what the command did from what the runtime did. |
| Deleting | `delete()` waits until `get` no longer finds the sandbox (60 s), or raises `delete_pending` | Cleanup is confirmed, not assumed. |
| Prover verdicts | Only `within_boundary` with all five coverage domains passes. The JSON's `schema_version`, `prover_version` and `exit_code` must match the process. Counterexamples are kept, truncated to 1 KiB | Every other result is a failure, as the prover's documentation requires. |
| Configuration | `AEGIS_SANDBOX_RUNTIME` is `none` (default) or `openshell`. With `none`, a `DisabledRuntime` refuses every operation with `sandbox_unavailable`. `AEGIS_OPENSHELL_GATEWAY` defaults to `openshell` | Disabling OpenShell never runs anything unsandboxed. |
| Doctor | An "NVIDIA OpenShell" check. It is `SKIP` (optional) with `none`. With `openshell` it is required: Landlock ABI at least 3, then `check()`, with a hint per detail code | `make doctor` shows exactly why sandboxes can't run. |
| Tests | A fake `openshell` and `openshell-prover` (`tests/fixtures/fake_openshell.py`) are real executables, so CI exercises the subprocess path, the environment and the arguments. Tests marked `openshell` run against the real gateway through `make test-openshell`. They never pull an image and fail with a hint when OpenShell or `ubuntu:24.04` is missing. CI does not run them (decision U7) | The contract is checked on every pull request; real enforcement is checked locally. |

## Consequences and limitations

- **Upgrades need re-verification.** Everything above holds for 0.1.6. An upgrade means changing `VERIFIED_VERSION`, re-running `make test-openshell` and updating this ADR. Consider `sudo apt-mark hold openshell`.
- **The workspace is not an access boundary.** The CLI identity is a Platform Admin on a local gateway, so a compromised worker could reach other workspaces through OpenShell directly. The adapter's allow-list and name checks are AEGIS code, not OpenShell enforcement.
- **Exit status 1 is ambiguous.** A gateway failure during `exec` can look like a command failing with 1. The `Ready` check before each exec narrows this, and the enforcement probes (Increment 3) add positive controls.
- **CLI error text is parsed in two places:** `not found` and `no global policy revision found`, after removing the wrapping. Both come from OpenShell itself, never from a workload.
- **Only `enforcement_check` runs in a sandbox** (ADR-0019). The policies AEGIS uses, and the prover gate around them, are in ADR-0017. Since Increment 4, `check()` also reports whether a failure may clear on its own (`RuntimeStatus.retryable`: `unreachable` and `not_connected`), so a task retries an unreachable gateway and fails on a refused one.
