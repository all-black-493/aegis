# ADR-0017: Sandbox policies, the prover gate and the probe image

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

The OpenShell adapter (ADR-0016) can create a sandbox from any policy file and any image. Before AEGIS runs anything in a sandbox (Increments 3 and 4), it needs:

- **Its own policies:** versioned and reviewed like `aegis.policy`.
- **Proof before use:** each sandbox's policy, as the sandbox actually enforces it, must be proven within an operator-owned boundary before anything runs in it.
- **A known image:** the sandbox must run exactly the image AEGIS built, not whatever a tag points to.
- **An audit trail:** a record of what was created and what was deleted.
- **Cleanup:** no sandbox may outlive its job.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Policies | `deploy/openshell/boundary.yaml` is the most any AEGIS sandbox may be granted. `deploy/openshell/probe.yaml` is the probe sandbox's policy. Both require Landlock `hard_requirement` and run as UID and GID 2000. They make `/usr`, `/lib`, `/etc`, `/proc` and `/dev/urandom` read-only and `/tmp` and `/dev/null` writable. They have no `include_workdir` and **no network rules**, so all egress is denied | Every sandbox is non-root, cannot run without its filesystem rules, and reaches nothing. |
| Fingerprint | `aegis.runtime.gate` hashes `SANDBOX_POLICY_VERSION` (`2026.11.02-1`) with the boundary, the probe policy and the probe Dockerfile. A unit test pins the fingerprint, so any change fails CI until the version and fingerprint are updated in the same reviewed change. Other tests pin the security-relevant lines themselves | A sandbox policy cannot change silently, as with `aegis.policy` (ADR-0007). |
| Probe image | `deploy/openshell/probe/Dockerfile` builds `FROM ubuntu@sha256:5616…38ea`, the local `ubuntu:24.04`, pinned by digest. It adds a dedicated `probe` user (UID and GID 2000, no supplementary groups, no login shell) and the release marker `/etc/aegis-probe-release`. `make openshell-image` builds it with `--pull=false --network none` and prints `AEGIS_OPENSHELL_IMAGE=sha256:…` (decision U3) | Nothing is downloaded, and the image's identity is one exact digest. |
| Image pin | AEGIS creates sandboxes from the **image ID** (`AEGIS_OPENSHELL_IMAGE`, which must be `sha256:` followed by 64 hex characters). OpenShell 0.1.6 with the Docker driver accepts an image ID for `--from`, and the workload container runs exactly that image (observed 2026-11-02) | A tag can be moved; an image ID cannot. |
| Gate | `SandboxGate.open(name, labels)` is a context manager. It refuses without an image (`image_missing`), checks the runtime (`check()`, which also refuses a global policy), and proves the probe policy against the boundary (`policy_refused`). It then creates the sandbox, proves its **effective** policy (`effective_policy_refused`) and reads the release marker (`image_unrecognised`). Only then does it record `created` and run the block. It always deletes the sandbox afterwards | Anything other than `within_boundary` with all five coverage domains stops the sandbox before it is used. The proof covers what the sandbox really enforces, including baseline paths, provider rules or a global policy. |
| Events | The gate reports `created` (sandbox ID, runtime version, image, policy version and fingerprint, OpenShell's `policy_hash`, prover result) and `deleted` (`completed`, `aborted`, `refused`, `orphaned`, or the runtime's error code) to a callback. It knows nothing of AEGIS's database | The gate stays inside the runtime layer (ADR-0016's layering rules) and is tested without a database. |
| Audit | `aegis.jobs.sandboxes.audit_sink` records each event as `sandbox.created` or `sandbox.deleted`, in its own transaction as it happens. The actor is `system:worker` and the target type `sandbox`. If the `created` write fails, the exception reaches the gate, which deletes the sandbox before it is used | No sandbox runs unaudited (fail closed). |
| Deletion | A failed deletion is recorded as `sandbox.deleted` with outcome `failure` and is not raised. Orphan cleanup removes the sandbox later | Cleanup errors never hide the original outcome. |
| Orphans | When the worker starts, `clean_orphaned_sandboxes` lists AEGIS's sandboxes (name, label and workspace, ADR-0016). It deletes each one unless its `aegis.job` label names a job that is `running` under an unexpired lease, and records `sandbox.deleted` (`orphaned`). If the runtime is unusable, the worker logs `sandbox cleanup skipped` and starts anyway, because no sandbox can be created then either | A sandbox never outlives the job that created it, and a running job's sandbox is never taken away. |
| Doctor | With `AEGIS_SANDBOX_RUNTIME=openshell`, the OpenShell check also requires `AEGIS_OPENSHELL_IMAGE` and that the image is present locally | `make doctor` says how to build it. |

## Consequences and limitations

- **No network rules yet.** A sandbox without network rules has no proxied path, so OpenShell writes no denial record for a refused connection (observed 2026-11-02). Increment 3 adds the canary endpoint to the probe policy and the boundary, so denials are logged as corroborating evidence.
- **The image ID is per machine.** Docker builds are not bit-reproducible, so each machine builds its own probe image and configures its own `AEGIS_OPENSHELL_IMAGE`. Audit records name the exact ID that ran.
- **The release marker is a recognition check, not a signature.** Any image could contain the same file. The image ID in the audit record is the real identity, and choosing the image is an operator decision like choosing the model (ADR-0013).
- **Orphan cleanup runs only at worker start.** A sandbox orphaned while workers keep running is removed the next time a worker starts. Increment 4 adds cleanup to the worker's recovery loop.
- **The workspace is shared with the live tests.** A worker starting during `make test-openshell` treats the tests' sandboxes, which have no job label, as orphans.
- **Nothing runs in these sandboxes yet.** The probes (Increment 3) and the `enforcement_check` task kind (Increment 4) use the gate.
