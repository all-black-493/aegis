# ADR-0018: Enforcement probes and independent verification

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Phase 3's acceptance criterion is that a controlled workload runs under actual OpenShell enforcement and that the expected restrictions are **independently verified**. Three things fall short of that:

- **The policy.** The prover (ADR-0017) shows what a sandbox's policy allows, not what the kernel and the proxy actually enforce.
- **OpenShell's own records.** They come from the enforcement point itself.
- **The sandbox's word.** A report written inside the sandbox could be wrong or forged.

AEGIS therefore needs its own evidence, gathered and judged outside the sandbox. It also needs positive controls, so that a broken sandbox is never mistaken for a restrictive one.

## Behaviour observed on OpenShell 0.1.6 (2026-11-02)

| Probe | Observed |
|---|---|
| Read a user-owned path missing from the policy; truncate or create in a user-owned read-only path; list `/.openshell`; read `/proc/1/environ` (PID 1 is the `openshell-sandbox` supervisor) | `Permission denied`. Unix permissions would allow the first three, so this is Landlock |
| `/proc/self/status` of an exec'd command | `NoNewPrivs: 1`, `CapEff: 0000000000000000`, `Seccomp: 2` with 6 filters |
| `GET /probe/…` from `/usr/bin/bash` to the canary rule (`protocol: rest`, `enforcement: enforce`) | Reaches the canary. OpenShell records `NET:OPEN … ALLOWED` and `HTTP:GET … ALLOWED` |
| `POST /probe/…`, or `GET /admin/…`, on the same allowed connection | OpenShell answers `403` with `{"error":"policy_denied","policy":"canary",…}`; the canary sees nothing. Recorded as `HTTP:POST … DENIED` or `HTTP:GET … DENIED` with an `L7_REQUEST` reason |
| `bash` to another canary port, to `192.0.2.1:443` or to `169.254.169.254:80`; `perl` to the allowed endpoint | `connect()` fails with `EACCES`; the canary sees nothing. Recorded as `NET:OPEN … DENIED <binary>(0) -> <host>:<port>`. The `perl` record can arrive after the probe returns |
| Sandbox names | Longer than 19 characters are refused (`name exceeds maximum length`) |

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Where | `aegis.runtime.probes`, with one responsibility per module: `model` (types), `catalog` (the fixed probes), `verdicts` (pure judging), `canary` (the host listener) and `suite` (the runner). It depends only on the runtime contract and the gate | It is testable without OpenShell, a database or a network, and no module grows into a catch-all. |
| Probes | 16 fixed probes, each one `sandbox exec` of an absolute program with a nonce substituted for this run. **Filesystem:** a scratch write and a read of a listed path (controls); a read of an unlisted path; a truncate and a create in a read-only path; `/.openshell`; the supervisor's environment; and the read-only file read again afterwards. **Process:** no new privileges, no capabilities, seccomp filtering. **Network:** an allowed `GET` to the canary (control); a forbidden method and a forbidden path on that connection; another port; another binary; an unrouted host; and the metadata address. Nothing comes from a task | What runs is AEGIS's own fixed code. Each result is the exit status the runtime reports, not something the sandbox wrote about itself. |
| Image and policy | The probe image (release 2) gives the probe user `/srv/aegis/readonly` (listed read-only) and `/srv/aegis/unlisted` (mode 700, not listed). A refusal there can only come from Landlock. The probe policy and the boundary allow one network rule: `GET /probe/**` from `/usr/bin/bash` to `172.17.0.1:18901`, with `protocol: rest` and `enforcement: enforce`, following OpenShell's guidance against uninspected or `audit` endpoints. The boundary also lists the baseline `/var/log` that OpenShell adds when a policy has a network rule. Policy version `2026.11.02-2` | Every restriction is checked where Unix permissions would not already refuse it. |
| Canary | While the probes run, AEGIS listens on `172.17.0.1:18901` and `:18902`, the default Docker bridge, and records each request's port and path. It answers `aegis-canary <path>`. If either port cannot be bound, the run fails with `canary_unavailable`. The unrouted host is TEST-NET-1 (`192.0.2.1`), so even a broken restriction sends nothing anywhere | AEGIS sees for itself whether a refused connection or request arrived, and the positive control needs no internet. |
| Judging | A restriction is **violated** if the canary received its request, whatever the sandbox printed, or if the action evidently happened (`exit 0`, the canary's reply, changed content, or a missing hardening flag). It is **held** if the expected refusal was observed (`EACCES`, `policy_denied`, or the marker unchanged). Anything else, including a timeout, is **inconclusive**. A control that fails, or a canary control that the canary did not see, is inconclusive | Absence of evidence never counts as enforcement. |
| Verdict | `violated` if any restriction is violated; otherwise `inconclusive` if anything is inconclusive; otherwise `verified`. An empty run is inconclusive | A run is verified only when every control worked and every restriction held. |
| OpenShell records | After the probes, `openshell logs NAME --source sandbox -n 2000` is read without `--level`, because a warning filter hides policy events. The shorthand OCSF lines are parsed into `EnforcementRecord`s. The suite polls up to five times, a second apart, until every expected record has arrived. Each network result is marked corroborated or not; **corroboration never decides an outcome** | The enforcement point's own account is reported beside AEGIS's evidence and can be checked against it, but it is not trusted on its own. |
| Lifecycle | `verify_enforcement` starts the canary, opens the gate (ADR-0017), runs the probes and returns the report. The sandbox is deleted and the canary stopped whatever happens | Nothing is left listening or running. |
| Names | `SANDBOX_NAME` allows `aegis-` plus 1–13 characters (19 in all), the most 0.1.6 accepts. The fake CLI refuses longer names as OpenShell does | Found by the live tests: the contract allowed names OpenShell refuses. |
| Tests | CI runs the judging against an in-process fake runtime and through the adapter against the fake CLI. Those runs include lying sandboxes, failed controls, timeouts, lagging records and refused sandboxes. Live tests (`make test-openshell`) run the real suite, which must be `verified` with every network result corroborated. They also widen the boundary and probe policy to let `perl` and any `GET` through: the gate admits that sandbox and the probes must report those two checks as `violated` | The evaluation is exercised on every pull request, and real enforcement locally. |

## Consequences and limitations

- **The canary address is host-specific.** The policies name the default Docker bridge, `172.17.0.1`. A host whose `docker0` uses another address gets `canary_unavailable` (fail closed) until the policies, a reviewed and fingerprinted change, are updated.
- **One run at a time per host.** The canary's ports are fixed, so a second concurrent run gets `canary_unavailable`.
- **The canary listens on the Docker bridge** for the length of a run. Any container on that bridge can reach it then; it serves a fixed reply and records only ports and paths.
- **Exit status 1 is still ambiguous** (ADR-0016), but no restriction is judged held on exit status alone: each needs a specific error message, the OpenShell refusal, or unchanged content.
- **The probes cover the default enforcement surface, not every OpenShell feature.** Providers, middleware, other protocols and GPUs are not exercised.
- **No task runs the probes yet.** `enforcement_check` (Increment 4) runs them through the API and the worker and audits the report.
