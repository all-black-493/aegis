# ADR-0012: Evaluation frameworks (DeepEval and DeepTeam)

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

AEGIS must be evaluated empirically (AGENTS.md §12; README §15–§16). Two open-source frameworks cover parts of that work:

- **DeepEval** measures the quality of LLM and agent runs.
- **DeepTeam** generates adversarial attacks and judges the target's responses.

Both rely mostly on LLM judges, and AGENTS.md §3.4 forbids an LLM from being the authority for any security decision. Their default models are hosted by OpenAI. DeepEval sends telemetry by default.

Facts verified on 2026-11-02 from the official documentation and PyPI metadata:

| | DeepEval 4.3.2 | DeepTeam 1.0.10 |
|---|---|---|
| Licence | Apache-2.0 | Apache-2.0 |
| Python | 3.9 up to, not including, 4.0 | 3.9 up to, not including, 3.14 |
| Relationship | — | Depends on `deepeval>=3.6.2` and uses its model classes for the attack simulator and the judge |
| Default models | OpenAI judges | Simulator `gpt-3.5-turbo-0125`, judge `gpt-4o` |
| Local models | `OllamaModel` or a custom `DeepEvalBaseLLM` | Accepts the same model objects |
| Network by default | PostHog telemetry until `DEEPEVAL_TELEMETRY_OPT_OUT=1`; uploads to Confident AI only when an API key is configured | Inherits DeepEval; its own network behaviour is to be verified before use |

A dry-run resolution against AEGIS's lockfile on Python 3.13 found three problems:

- **Version conflict.** DeepEval requires `click<8.4.0`, and AEGIS locks `click==8.5.0`. uv keeps one lockfile for every dependency group, so a group inside the AEGIS project would downgrade `click` for the runtime, or would need a forked lock.
- **Size.** Together the two frameworks resolve to 68 packages, including `openai`, `grpcio`, the OpenTelemetry SDK and `posthog`.
- **Pytest plugins.** DeepEval declares `pytest-asyncio`, `pytest-repeat`, `pytest-rerunfailures` and `pytest-xdist` as ordinary dependencies. These would load into every AEGIS test run.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Role | Both are evaluation instruments. They measure AEGIS and the agents running in it. Neither is part of the application, a security control, or a source of evidence. Their scores never authorize an action and never establish a security outcome on their own. | AGENTS.md §3.4: no LLM is a security boundary. |
| When | DeepEval arrives with single-agent execution (Phase 4). DeepTeam arrives with the adversarial benchmark (Phase 10), after OpenShell (3), provenance and audit (5), approvals (6) and evidence (7) exist to attack. Phases 7, 8, 9, 11 and 12 extend their use (README §11). Phase 2 is unchanged. | There is nothing worth evaluating or attacking before agents exist. Earlier adoption would bring the dependencies for no research value. |
| Packaging | `benchmarks/` becomes a separate, non-packaged uv project with its own `pyproject.toml` and lockfile. It holds the evaluation harness and both frameworks. It is not a second AEGIS distribution (ADR-0001) and does not import `aegis`. | Avoids the `click` conflict, keeps 68 packages and their pytest plugins out of AEGIS's environment and tests, and lets the evaluation stack keep its own Python constraint. |
| Boundary | The harness is an external client. It submits work through AEGIS's public API with synthetic identities and reads outcomes through a read-only path: `GET /v1/tasks/{id}/steps` (ADR-0022). `src/aegis` must not import `deepeval` or `deepteam`; `tests/unit/test_layering.py` enforces this. | Keeps evaluation off the enforcement path. An outage of either framework cannot affect AEGIS. |
| Security outcomes | Deterministic assertions over AEGIS's records decide whether an attack succeeded: audit events, decisions, history, OpenShell enforcement evidence and canary secrets. DeepTeam's verdicts are recorded beside them, with their agreement rate. | The truth of a security outcome is in the records, not in a model's reading of a response. |
| Agent metrics | The harness builds DeepEval test cases from AEGIS's execution records after each run. DeepEval's `@observe` tracing is not added to AEGIS code. Whether any trace-only metric (`TaskCompletionMetric`, `StepEfficiencyMetric`, `PlanAdherenceMetric`) can be fed from records is verified in Phase 4, not assumed. | Tracing inside agents would put DeepEval and its telemetry on the execution path. |
| Guardrails | DeepTeam's guardrails are not used as AEGIS controls. | They are LLM classifiers. |
| Judges | Judges and attack simulators use local models only: Ollama, pinned by digest, temperature 0, and never the model under test. The harness refuses to run if a framework would fall back to a hosted default. Using a remote judge needs explicit approval and its own handling of credentials. | Independence, reproducibility, and no data leaving the machine. |
| Telemetry and uploads | The harness sets `DEEPEVAL_TELEMETRY_OPT_OUT=1`, configures no Confident AI key, and keeps uploads off. DeepEval's local store is redirected into each run's result folder. DeepTeam's network behaviour is verified before its first use. | No evaluation data leaves the machine. |
| Data ownership | Audit stays in PostgreSQL and evidence in the evidence store. Telemetry goes to OpenTelemetry and LLM traces to Langfuse. Datasets are versioned files in `benchmarks/datasets/`. Results and experiment records are versioned result files, never the audit tables. | Every kind of record has one system of record. |
| Reproducibility | Every result records the benchmark, scenario and dataset versions and the dataset hash; the configuration (A, B or C); the AEGIS commit and the policy version and fingerprint; the OpenShell version and policy; the tested and judge models with their digests; the framework versions, metric configuration and thresholds; and the task, decision and audit identifiers with timestamps. | Results stay comparable, and any difference between them stays visible. |
| Judge reliability | Each metric is calibrated against a human-labelled set, and its agreement and false-positive and false-negative rates are reported with every result. Thresholds are versioned. Model-dependent outcomes get repeated trials with confidence intervals. A new judge or threshold starts a new result series. | An uncalibrated judge's score is not a measurement. |
| Adversarial safety | Attacks target only disposable deployments: a separate `*_eval` database, generated synthetic secrets and canary credentials, never the developer's `.env` secrets or real data. Agent workloads run only under verified OpenShell, and without it the adversarial runner refuses to start. Attack prompts and outputs are hostile data: never executed, redacted in reports, kept in the run folder. | Adversarial testing must not create new exposure. |
| CI | Model-based suites run in a separate, scheduled, non-blocking workflow from the evaluation environment (Phase 11). The deterministic suites remain the required checks. The evaluation lockfile is covered by dependency scanning and the SBOM. | A model's verdict never gates an ordinary pull request. |

## Consequences and limitations

- **Nothing is implemented yet.** The import rule exists now; the rest arrives with Phases 4 and 10.
- **Facts may change.** The versions and behaviour above were verified on 2026-11-02 and are re-verified when each framework is first installed. In particular:
  - DeepTeam's Python ceiling (below 3.14) constrains the evaluation environment;
  - API changes may affect which metrics can be built from records.
- **Some metrics may not fit.** DeepEval's trace-only agent metrics may prove unusable without tracing inside agent code. If so, they are not used; any exception needs a new ADR.
- **Resources.** Local judges need memory and time; the judge model is chosen and pinned in Phase 4.
- **A second dependency set.** The separate project means a second lockfile to keep up to date and to scan.
