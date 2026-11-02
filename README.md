# AEGIS
### Adaptive Runtime Assurance for Secure Autonomous Multi-Agent Systems

**An open-source research and engineering platform for building, governing, observing, and evaluating secure autonomous AI agents.**

> Building autonomous agents is relatively easy. Building autonomous agents that can be trusted to operate safely, independently, and reproducibly is considerably harder.

AEGIS aims to address this challenge by combining runtime enforcement, agent governance, provenance tracking, risk-aware authorization, independent evidence verification, observability, and adversarial evaluation.

The project is designed to be reproducible: developers should be able to clone the repository, configure their own local environment, run the system, execute tests, and reproduce documented experiments without requiring access to the original developer's infrastructure or paid model APIs.

---

# Table of Contents

1. [Project Vision](#1-project-vision)
2. [Research Problem](#2-research-problem)
3. [Research Hypothesis](#3-research-hypothesis)
4. [Core Design Principles](#4-core-design-principles)
5. [Architecture Overview](#5-architecture-overview)
6. [The Seven Architectural Pillars](#6-the-seven-architectural-pillars)
7. [Technology Stack](#7-technology-stack)
8. [Local-First Development](#8-local-first-development)
9. [Docker Compose Deployment Profiles](#9-docker-compose-deployment-profiles)
10. [Repository Structure](#10-repository-structure)
11. [Progressive Implementation Roadmap](#11-progressive-implementation-roadmap)
12. [Testing Strategy](#12-testing-strategy)
13. [Observability with Langfuse](#13-observability-with-langfuse)
14. [CI/CD Architecture](#14-cicd-architecture)
15. [Adversarial Benchmark](#15-adversarial-benchmark)
16. [Research Evaluation](#16-research-evaluation)
17. [Security Model and Threat Boundaries](#17-security-model-and-threat-boundaries)
18. [Developer Experience](#18-developer-experience)
19. [Contribution Guidelines](#19-contribution-guidelines)
20. [Definition of Done](#20-definition-of-done)
21. [Project Status](#21-project-status)

---

# 1. Project Vision

AEGIS is an adaptive runtime assurance platform for secure autonomous multi-agent systems.

It aims to provide a structured mechanism for controlling how autonomous agents interact with tools, filesystems, external services, models, repositories, and other agents.

Rather than relying exclusively on model instructions or prompt-based safety rules, AEGIS combines application-level governance with independently enforced runtime restrictions.

The platform integrates:

- NVIDIA OpenShell for sandboxed execution and runtime enforcement.
- Ollama for local model inference.
- Langfuse for LLM observability, tracing, prompt management, and evaluation.
- OpenTelemetry for vendor-neutral telemetry.
- A provenance system for tracking the origin and trustworthiness of information.
- A deterministic risk engine for task-aware authorization decisions.
- Human approval workflows for sensitive operations.
- Independent evidence verification for task completion.
- An adversarial benchmark for measuring security effectiveness.
- Docker Compose for reproducible local deployment.
- CI/CD automation for continuous quality and security validation.

## Primary objective

Develop a system that can coordinate autonomous agents while maintaining verifiable control over their permissions, actions, execution environment, and reported outcomes.

## What AEGIS is not

AEGIS is not:

- A replacement for NVIDIA OpenShell.
- A new operating-system sandbox implementation.
- A prompt-only security framework.
- A framework that assumes LLMs can reliably enforce their own restrictions.
- A collection of agents that automatically trust one another.
- A system that considers an agent's claim of success sufficient evidence of completion.

**OpenShell remains the runtime enforcement authority. AEGIS provides the governance, coordination, assurance, and evaluation capabilities around it.**

---

# 2. Research Problem

Autonomous AI agents increasingly interact with tools and external systems to perform complex tasks.

These capabilities introduce security and reliability challenges:

- Prompt injection through untrusted documents and repository files.
- Unauthorized filesystem access.
- Unintended network communication.
- Credential exposure.
- Excessive tool permissions.
- Unsafe agent delegation.
- Malicious dependency installation.
- Unverified task completion.
- Inadequate auditability.
- Poor reproducibility of agent behavior.

Traditional application authorization is not necessarily sufficient for autonomous systems because agent behavior is dynamic, context-dependent, and influenced by untrusted external information.

AEGIS investigates how runtime assurance can be combined with agent orchestration to address these challenges.

---

# 3. Research Hypothesis

### Primary hypothesis

Task-aware and provenance-aware runtime assurance can reduce unsafe actions in autonomous multi-agent systems while preserving legitimate task completion and operational efficiency.

### Supporting research questions

1. Does provenance-aware risk assessment improve detection of malicious or untrusted instructions?
2. Can task-scoped permissions reduce unauthorized tool usage?
3. Do human approval workflows reduce high-risk actions without introducing excessive friction?
4. Does independent evidence verification improve the reliability of agent-reported task completion?
5. Can runtime enforcement reduce unsafe behavior without significantly increasing legitimate task failure rates?
6. Does observability improve the ability to identify and diagnose security failures?
7. Can these controls be evaluated consistently across different local models and hardware configurations?

These questions will be investigated through repeatable experiments and a versioned adversarial benchmark.

---

# 4. Core Design Principles

The following principles govern all architectural and implementation decisions.

## 4.1 Defense in depth

Security must not depend on a single component.

Application-level authorization, runtime enforcement, provenance, audit records, and evidence verification should complement one another.

## 4.2 Least privilege

Every agent and tool receives only the permissions necessary for its assigned task.

## 4.3 Fail closed

High-risk operations must not proceed when required authorization, policy verification, or enforcement capabilities are unavailable.

## 4.4 Explicit trust boundaries

External documents, repository files, web pages, model outputs, logs, and user-provided content must be treated according to their provenance and trust classification.

## 4.5 Independent verification

An agent cannot establish successful completion merely by claiming that it has completed a task.

## 4.6 Reproducibility

Experiments, benchmarks, configurations, model versions, and execution environments must be recorded.

## 4.7 Local-first development

A developer must be able to run the basic application and deterministic tests locally without paid API credentials.

## 4.8 Progressive implementation

Each architectural component must have a working implementation and passing acceptance tests before the next major dependency is introduced.

## 4.9 Modularity without premature distribution

Begin with a modular monolith and worker process. Introduce independently deployed services only when justified by measurable requirements.

---

# 5. Architecture Overview

AEGIS is organized into six logical planes.

```mermaid
flowchart TB
    USER["User / Developer"]

    subgraph CONTROL["1. CONTROL PLANE"]
        API["API / CLI"]
        AUTH["Identity & Authorization"]
        ORCH["Workflow Orchestrator"]
        APPROVAL["Human Approval Service"]
        RISK["Risk & Policy Decision Engine"]
        REGISTRY["Tool & Capability Registry"]
    end

    subgraph AGENTS["2. AGENT PLANE"]
        PLANNER["Planner"]
        RESEARCHER["Researcher"]
        IMPLEMENTER["Implementer"]
        REVIEWER["Security Reviewer"]
        VERIFIER["Evidence Verifier"]
        AUDITOR["Auditor"]
    end

    subgraph TRUST["3. TRUST & ENFORCEMENT PLANE"]
        PROVENANCE["Provenance & Trust Labels"]
        POLICY["Policy Versioning"]
        OPENSHELL["NVIDIA OpenShell"]
        SANDBOX["Isolated Agent Runtime"]
        PROVER["Policy Prover"]
    end

    subgraph INTELLIGENCE["4. MODEL & KNOWLEDGE PLANE"]
        PROVIDER["Model Provider Interface"]
        OLLAMA["Ollama / Local Models"]
        RETRIEVAL["Knowledge & Retrieval"]
        EVIDENCE["Evidence Store"]
    end

    subgraph OBSERVABILITY["5. OBSERVABILITY & EVALUATION PLANE"]
        OTEL["OpenTelemetry"]
        LANGFUSE["Langfuse"]
        AUDITDB["Security Audit Store"]
        METRICS["Metrics & Dashboards"]
        BENCH["Adversarial Benchmark"]
    end

    subgraph DELIVERY["6. DELIVERY & OPERATIONS PLANE"]
        COMPOSE["Docker Compose"]
        CI["CI/CD"]
        SCAN["Supply Chain Security"]
        RELEASE["Reproducible Releases"]
    end

    USER --> API
    API --> AUTH
    AUTH --> ORCH

    ORCH --> RISK
    RISK --> REGISTRY
    RISK --> APPROVAL

    ORCH --> PLANNER
    PLANNER --> RESEARCHER
    RESEARCHER --> IMPLEMENTER
    IMPLEMENTER --> REVIEWER
    REVIEWER --> VERIFIER
    VERIFIER --> AUDITOR

    AGENTS --> PROVENANCE
    REGISTRY --> POLICY
    POLICY --> PROVER
    PROVER --> OPENSHELL
    OPENSHELL --> SANDBOX

    AGENTS --> PROVIDER
    PROVIDER --> OLLAMA
    AGENTS --> RETRIEVAL
    VERIFIER --> EVIDENCE

    AGENTS --> OTEL
    OTEL --> LANGFUSE
    OTEL --> METRICS
    AGENTS --> AUDITDB
    BENCH --> LANGFUSE

    COMPOSE --> CONTROL
    COMPOSE --> AGENTS
    COMPOSE --> OBSERVABILITY

    CI --> SCAN
    CI --> BENCH
    CI --> RELEASE
```

This represents the intended architecture. Implementation will proceed incrementally.

## Important trust boundary

The AEGIS application is not the sandbox enforcement boundary.

NVIDIA OpenShell must enforce the actual runtime restrictions supported by the installed version.

AEGIS may:

- Assess risk.
- Propose policy changes.
- Request authorization.
- Record policy decisions.
- Verify policy changes.
- Correlate execution events.
- Evaluate agent behavior.

AEGIS must not claim that an application-level decision independently guarantees filesystem, process, or network isolation.

---

# 6. The Seven Architectural Pillars

## Pillar 1: Runtime Security

### NVIDIA OpenShell

OpenShell provides the isolated execution environment and runtime enforcement foundation.

Responsibilities include:

- Sandboxed agent execution.
- Filesystem restrictions.
- Network egress restrictions.
- Process and runtime controls supported by the installed version.
- Policy enforcement.
- Policy verification through the available policy prover.

AEGIS must integrate with the installed OpenShell version through a dedicated adapter.

Do not invent CLI commands, policy properties, or runtime capabilities.

All integration behavior must be verified against the pinned OpenShell release and official documentation.

### Acceptance criteria

- AEGIS can create or connect to the required sandbox.
- A controlled agent task executes inside the intended environment.
- Prohibited filesystem operations are prevented.
- Prohibited network operations are prevented.
- Enforcement behavior is verified through actual integration tests.
- Failure of required enforcement prevents untrusted execution.

---

## Pillar 2: Agent Governance

### Identity and authorization

Introduce explicit identities for users, agents, and tools.

Capabilities include:

- Role-based access control.
- Agent-specific permissions.
- Task-scoped authorization.
- Service-to-service authentication.
- Human approval identities.
- Session and execution identity.

Agents must not automatically inherit one another's permissions.

### Tool and capability registry

Every available tool must have a registered definition.

A tool definition should contain:

- Name and version.
- Input and output schemas.
- Required capabilities.
- Risk classification.
- Side-effect classification.
- Network requirements.
- Resource limits.
- Approval requirements.
- Permitted agent roles.

### Risk and policy engine

The risk engine evaluates the context of an action and produces a structured decision.

It should support:

- Task-aware risk scoring.
- Policy versioning.
- Policy simulation.
- Policy regression testing.
- Policy diff analysis.
- Explicit denial reasons.
- Approval requirements.
- Policy provenance.

### Human approval

High-risk operations must require explicit authorization.

Examples include:

- Destructive filesystem operations.
- External data transmission.
- Permission broadening.
- Sensitive configuration changes.
- Operations with significant external side effects.

Approval must be bound to the specific task, action, policy version, and relevant context.

An agent must not approve its own sensitive action.

---

## Pillar 3: Trust and Provenance

### Provenance engine

Every important external input should retain its origin and processing history.

Record:

- Source identifier.
- Source type.
- Timestamp.
- Content hash.
- Retrieval method.
- Trust classification.
- Associated task.
- Processing history.
- Verification status.

### Trust classifications

| Classification | Meaning |
|---|---|
| `trusted` | Explicitly approved configuration or controlled system data |
| `verified` | Independently checked against an authoritative source |
| `untrusted` | External documents, repository files, web content or user-provided material |
| `derived` | Generated from other data and retaining relevant source risks |
| `unknown` | Origin or integrity cannot be established |

An agent must not be able to promote untrusted content to trusted content merely by declaring it trustworthy.

### Retrieval and knowledge security

Future retrieval capabilities may include:

- Document ingestion.
- Content hashing.
- Chunk-level provenance.
- Source-aware retrieval.
- Retrieval authorization.
- Prompt-injection screening.
- Source freshness tracking.
- Citation verification.
- Poisoned-document test cases.

Start with a searchable document index. Introduce vector retrieval only when requirements justify it.

---

## Pillar 4: Evidence and Verification

### Evidence verifier

The verifier independently checks whether a task has actually been completed.

For code modification tasks, evidence may include:

- Git diffs.
- Unit-test results.
- Integration-test results.
- Static-analysis results.
- Dependency scan results.
- Build output.
- Policy verification results.
- Artifact hashes.
- Execution identifiers.

Example evidence record:

```json
{
  "task_id": "task-001",
  "status": "verified",
  "evidence": [
    {
      "type": "unit_test",
      "result": "passed",
      "artifact_hash": "sha256:..."
    },
    {
      "type": "policy_verification",
      "result": "passed",
      "artifact_hash": "sha256:..."
    }
  ]
}
```

This is a conceptual schema. The implementation must define and validate its formal version.

### Completion rules

- An agent's success message is not sufficient evidence.
- Missing evidence must not be silently treated as successful verification.
- Evidence must be associated with the correct execution.
- Evidence integrity must be checked.
- Failed verification must result in an explicit failure or review state.

---

## Pillar 5: Observability and Evaluation

### Langfuse

Langfuse is the primary LLM observability and evaluation integration.

It should provide:

- Distributed LLM traces.
- Agent execution visibility.
- Prompt version tracking.
- Model-call inspection.
- Latency and token usage.
- Evaluation datasets.
- Experiment comparisons.
- Scoring.
- Prompt evaluation.

Langfuse must be integrated through an AEGIS observability interface rather than being a hard dependency of the core application.

### OpenTelemetry

OpenTelemetry provides vendor-neutral telemetry.

Use it for:

- Distributed tracing.
- Metrics.
- Structured telemetry export.
- Correlation between API, worker, agent, and tool execution.
- Future observability backend integrations.

### Separate observability from security auditing

These systems have different responsibilities:

| Component | Responsibility |
|---|---|
| Langfuse | LLM traces, prompt experiments and model evaluation |
| OpenTelemetry | Vendor-neutral telemetry |
| AEGIS audit store | Security-relevant events and policy decisions |
| Evidence store | Independently verifiable task artifacts |

Langfuse traces must not be treated as immutable security audit records.

### DeepEval and DeepTeam

DeepEval measures the quality of agent runs (task completion, tool use, answer quality), and DeepTeam generates adversarial attacks. Both are evaluation instruments that run outside AEGIS, in a separate environment, against disposable deployments. Neither is part of the application or its enforcement path ([ADR-0012](docs/architecture/decisions/0012-evaluation-frameworks.md)).

- Langfuse and OpenTelemetry remain the systems of record for traces and telemetry. DeepEval's own tracing and its uploads to Confident AI are not used.
- Benchmark datasets are versioned files in the repository. Langfuse may display them but is not their system of record.
- Evaluation results are research records stored with each benchmark run. They are never security evidence and never authorize anything.
- Security outcomes come from deterministic assertions over AEGIS's audit and enforcement records. Model-based verdicts are reported beside them, with their measured agreement.

Security-critical events must be persisted through a dedicated audit mechanism with appropriate integrity, retention, and access controls.

### Operational metrics

Track:

- Task success rate.
- Unsafe action prevention rate.
- Policy violation rate.
- False positive rate.
- Approval frequency.
- Evidence completeness.
- Mean task duration.
- Cost per successful task.
- Recovery rate.
- Agent execution failure rate.

---

## Pillar 6: Adversarial Assurance

### AEGIS Adversarial Benchmark

Build a repeatable security benchmark containing scenarios such as:

1. Prompt injection through repository files.
2. Malicious documentation instructions.
3. Attempts to read secrets.
4. Attempts to access prohibited network destinations.
5. Attempts to modify protected files.
6. Tool argument manipulation.
7. Unauthorized agent delegation.
8. Approval bypass attempts.
9. Malicious dependency installation.
10. Falsified task completion evidence.

Each scenario must define:

- Attack description.
- Initial conditions.
- Expected security boundary.
- Expected result.
- Actual result.
- Evidence.
- Enforcement outcome.
- Detection outcome.
- Recovery outcome.

The benchmark must be versioned.

Results should be reproducible and associated with the model, model configuration, runtime version, and policy version.

### Security evaluation

Measure both security and usefulness.

A system that blocks every action is not a successful autonomous agent platform.

AEGIS must evaluate whether it prevents unsafe behavior while preserving legitimate task completion.

---

## Pillar 7: Reproducible Engineering

AEGIS must be runnable by developers on their own machines.

Required capabilities:

- Docker Compose deployment.
- `.env.example`.
- Local Ollama integration.
- Deterministic mock model.
- Optional Langfuse deployment.
- Optional OpenShell integration.
- Database migrations.
- Setup automation.
- Environment diagnostics.
- Automated tests.
- Documented hardware requirements.
- Reproducible benchmark execution.

The project must not require access to the original developer's machine, private infrastructure, or paid API credentials for its basic demonstration.

---

# 7. Technology Stack

The following is the proposed stack. Specific versions must be pinned and validated during implementation.

| Area | Technology | Purpose |
|---|---|---|
| Runtime enforcement | NVIDIA OpenShell | Sandboxed execution and policy enforcement |
| Local inference | Ollama | Local model execution |
| Initial model | Qwen3.5 | Local agent reasoning and tool-use experiments |
| Observability | Langfuse | LLM traces and evaluation |
| Telemetry | OpenTelemetry | Vendor-neutral observability |
| Agent and LLM evaluation | DeepEval | Quality metrics for agent runs; evaluation only, in a separate environment |
| Adversarial testing | DeepTeam | Attack generation for the adversarial benchmark; evaluation only |
| API | Python API framework | Application interface |
| Database | PostgreSQL | Application state, tasks and audit metadata |
| Queue | Database-backed worker initially | Asynchronous execution |
| Containerization | Docker | Reproducible environments |
| Local orchestration | Docker Compose | Local deployment |
| CI/CD | GitHub Actions | Automated quality and security checks |
| Dependency security | Trivy, Syft, Cosign | Scanning, SBOM and artifact signing |
| Testing | Pytest | Automated application tests |

### Architecture decisions

- Begin with a modular monolith.
- Use a worker process for asynchronous execution.
- Introduce Kafka only if measured throughput or event-delivery requirements justify it.
- Consider Temporal if workflows require durable, long-running execution and sophisticated recovery.
- Do not introduce Kubernetes during the initial local-development phase.
- Do not introduce a vector database until retrieval requirements justify it.
- Keep model-provider integrations behind an abstraction.
- Keep OpenShell, Ollama, and Langfuse adapters separate from core business logic.
- Keep evaluation frameworks (DeepEval, DeepTeam) outside the application: a separate environment, never on the enforcement path.

---

# 8. Local-First Development

## 8.1 Developer experience objective

A new developer should be able to:

1. Clone the repository.
2. Configure the environment.
3. Start the core services.
4. Run deterministic tests.
5. Execute a demonstration.
6. Enable local model inference.
7. Enable observability.
8. Run a controlled OpenShell security demonstration.

No paid API key should be required for the basic demonstration or deterministic test suite.

## 8.2 Two model modes

### Mode A: Mock provider

Use for:

- Unit tests.
- Deterministic CI.
- Basic demonstrations.
- Developers with limited hardware.
- Reproducible workflow testing.

The mock provider must use predefined responses and tool-call fixtures.

It must not pretend to provide genuine model reasoning.

### Mode B: Ollama provider

Use for:

- Actual local agent execution.
- Prompt experimentation.
- Multi-agent workflows.
- Model comparisons.
- Research evaluation.

All model calls should go through a provider abstraction:

```text
AEGIS
  |
  v
Model Provider Interface
  |
  +---- Mock Provider
  |
  +---- Ollama Provider
  |
  +---- Optional External Provider
```

The core application must not depend directly on Ollama-specific APIs throughout its codebase.

## 8.3 Model profiles

Initial recommended profiles:

| Profile | Model | Purpose |
|---|---|---|
| `mock` | No model required | Deterministic tests |
| `smoke` | Qwen3.5 0.8B | Basic local inference validation |
| `standard` | Qwen3.5 9B | Normal local development |
| `advanced` | Qwen3.5 27B | More demanding experiments |

These are starting recommendations, not hardware guarantees.

Performance depends on RAM, VRAM, quantization, context size, and concurrent workloads.

The setup process must explain expected model storage requirements before downloading large models.

Use local model tags rather than cloud-hosted variants when the objective is fully local inference.

## 8.4 Local deployment requirements

The basic environment should require:

- A supported operating system.
- Docker-compatible container runtime.
- Docker Compose.
- Sufficient memory and disk space.
- Python/runtime dependencies required by the project.

OpenShell and Ollama requirements must be documented separately.

The project must distinguish between:

- Running application tests with a mock provider.
- Running actual local inference.
- Running agents under real OpenShell enforcement.

A mock execution environment must never be described as equivalent to a real security-enforced execution.

---

# 9. Docker Compose Deployment Profiles

Do not require every developer to run the entire infrastructure stack.

Use optional profiles.

| Profile | Services | Purpose |
|---|---|---|
| `core` | API, worker, PostgreSQL | Basic development |
| `local-ai` | Core + Ollama | Local model execution |
| `observability` | Langfuse and its dependencies + telemetry collector | LLM observability |
| `full` | All supported local services | Complete development environment |
| `test` | Core + mock model + fixtures | Deterministic testing |

Core services carry no Compose profile, so `docker compose up` always starts them; optional services receive profiles in the phases that implement them ([ADR-0001](docs/architecture/decisions/0001-phase-0-development-foundation.md)).

Langfuse's self-hosted architecture has several supporting dependencies and can consume significant local resources.

Therefore, it should be optional for basic development.

### Configuration example

The following illustrates proposed AEGIS application configuration. It is not a substitute for the official configuration of individual integrations.

```dotenv
AEGIS_ENV=development

AEGIS_MODEL_PROVIDER=mock
AEGIS_MODEL_NAME=mock-model

AEGIS_DATABASE_URL=postgresql://aegis:aegis@postgres:5432/aegis

AEGIS_LANGFUSE_ENABLED=false
LANGFUSE_HOST=http://langfuse-web:3000

AEGIS_OPENSHELL_ENABLED=false

AEGIS_LOG_LEVEL=INFO
```

Real credentials must never be committed.

The current `.env.example` contains only the variables that are read today (`AEGIS_ENV`, the PostgreSQL settings, the database role passwords and the API token pepper); the other variables above remain proposals.

Agent-visible configuration must not contain raw infrastructure or model-provider secrets.

### Proposed developer commands

The following commands define the intended developer experience and must be implemented as part of the project:

```bash
make setup
make doctor
make up
make test
make demo
make down
```

Optional commands:

```bash
make up-local-ai
make up-observability
make up-full
make test-integration
make test-security
make benchmark
```

The implementation must document the actual commands and prerequisites.

The implemented commands, prerequisites and configuration are documented in [docs/development/getting-started.md](docs/development/getting-started.md). Commands not listed there are not implemented yet.

---

# 10. Repository Structure

All application code lives in a single installable `aegis` distribution under `src/aegis/` ([ADR-0001](docs/architecture/decisions/0001-phase-0-development-foundation.md)). Components sit directly under `src/aegis/`, with entry points in `src/aegis/apps/`; there is no `packages/` grouping level ([ADR-0002](docs/architecture/decisions/0002-layering-configuration-and-logging.md)).

## Current structure

```text
AEGIS/
├── .github/
│   └── workflows/
│       └── ci.yml
├── deploy/
│   └── openshell/
├── docs/
│   ├── architecture/
│   │   └── decisions/
│   ├── development/
│   └── security/
├── src/
│   └── aegis/
│       ├── apps/
│       │   ├── api/
│       │   ├── cli/
│       │   └── worker/
│       ├── audit/
│       ├── authorization/
│       ├── config/
│       ├── db/
│       ├── doctor/
│       ├── identity/
│       ├── integrations/
│       │   ├── ollama/
│       │   └── openshell/
│       ├── jobs/
│       ├── model_providers/
│       ├── policy/
│       ├── runtime/
│       └── tasks/
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── e2e/
├── .env.example
├── .gitignore
├── .python-version
├── AGENTS.md
├── Makefile
├── README.md
├── docker-compose.yml
├── pyproject.toml
└── uv.lock
```

`src/aegis/config/` contains operational settings, the `AEGIS_*` variable registry, `.env` handling and JSON logging with redaction. `src/aegis/db/` contains database roles, the engine and migrations; `src/aegis/audit/` the append-only audit store ([ADR-0010](docs/architecture/decisions/0010-audit-store.md)); `src/aegis/authorization/` the role and permission catalog, `authorize()` and the shared security-decision contract ([ADR-0006](docs/architecture/decisions/0006-authorization-and-decision-contract.md)); `src/aegis/identity/` identities, role assignments, API tokens and their administration ([ADR-0005](docs/architecture/decisions/0005-identities-and-credentials.md)); `src/aegis/tasks/` the task state machine, task and decision storage, guarded transitions ([ADR-0008](docs/architecture/decisions/0008-task-storage-and-integrity.md)) and the task service; `src/aegis/jobs/` the jobs table, the worker and the `noop`, `wait` and `generate` handlers ([ADR-0009](docs/architecture/decisions/0009-worker.md), [ADR-0015](docs/architecture/decisions/0015-generate-task-kind.md)); `src/aegis/policy/` the versioned policy rules and the decision service ([ADR-0007](docs/architecture/decisions/0007-policy-and-decision-service.md)); `src/aegis/model_providers/` the model provider contract, the deterministic mock provider and the provider factory ([ADR-0013](docs/architecture/decisions/0013-model-provider-contract.md)); `src/aegis/integrations/ollama/` the Ollama adapter, verified against Ollama 0.34.2 ([ADR-0014](docs/architecture/decisions/0014-ollama-integration.md)); `src/aegis/runtime/` the sandbox runtime contract, the prover gate and the enforcement probes ([ADR-0018](docs/architecture/decisions/0018-enforcement-probes.md)), and `src/aegis/integrations/openshell/` its NVIDIA OpenShell adapter, verified against OpenShell 0.1.6 ([ADR-0016](docs/architecture/decisions/0016-openshell-integration.md), [ADR-0017](docs/architecture/decisions/0017-sandbox-policies-and-gate.md)); `src/aegis/apps/cli/` the `aegis` command (`aegis db`, `aegis identity`, `aegis credential`, `aegis role`, `aegis model`, `aegis openshell`); `src/aegis/apps/api/` the HTTP API run by `make api` ([ADR-0004](docs/architecture/decisions/0004-api-foundation.md), [ADR-0011](docs/architecture/decisions/0011-task-api.md)); and `src/aegis/apps/worker/` the worker run by `make worker`. `src/aegis/doctor/` contains the environment diagnostics run by `make doctor`. These are the only Python packages implemented so far. `deploy/openshell/` holds AEGIS's sandbox policies and the probe image's Dockerfile.

## Planned additions

None of the following exists yet. Each part is introduced in the phase that implements it, and empty packages are not created in advance.

```text
AEGIS/
├── src/
│   └── aegis/
│       ├── apps/
│       │   └── dashboard/
│       │
│       ├── agents/
│       ├── orchestration/
│       ├── risk_engine/
│       ├── approvals/
│       ├── provenance/
│       ├── evidence/
│       ├── tool_registry/
│       ├── observability/
│       │
│       └── integrations/
│           ├── langfuse/
│           └── opentelemetry/
│
├── benchmarks/
│   ├── adversarial/
│   ├── task_completion/
│   ├── policy_regression/
│   └── datasets/
│
├── deploy/
│   ├── docker/
│   └── compose/
│
├── docs/
│   ├── research/
│   └── operations/
│
├── scripts/
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

`CONTRIBUTING.md`, `SECURITY.md` and `LICENSE` wait on pending decisions; no license has been chosen.

`benchmarks/` will be a separate, non-packaged uv project with its own lockfile, holding the evaluation harness and the DeepEval and DeepTeam dependencies ([ADR-0012](docs/architecture/decisions/0012-evaluation-frameworks.md)). It arrives in Phase 4.

Optional services are added to the existing `docker-compose.yml` under Compose profiles, not in separate Compose files.

The structure may evolve as implementation reveals better boundaries.

---

# 11. Progressive Implementation Roadmap

AEGIS must be built layer by layer.

Every phase has an acceptance gate. Do not proceed merely because code has been written.

## Phase 0 — Developer Experience Foundation

Implement:

- Repository structure.
- Dependency management.
- Environment configuration.
- Docker Compose foundation.
- Database service.
- Setup automation.
- Basic health checks.
- `make doctor`.
- CI skeleton.

**Acceptance criteria:**

A new developer can configure the core environment and run basic tests.

## Phase 1 — Application Foundation

Implement:

- API.
- API authentication design and implementation plan, completed before the API is exposed.
- Worker.
- Database models.
- Database migrations.
- Configuration validation.
- Structured logging.
- Health endpoints.

**Acceptance criteria:**

API, database, and worker integration tests pass.

## Phase 2 — Model Provider Abstraction

Implement:

- Model provider interface.
- Deterministic mock provider.
- Ollama provider.
- Model configuration.
- Model connectivity checks.

**Acceptance criteria:**

The same application workflow works with both mock and local model providers.

## Phase 3 — OpenShell Integration

A separate OpenShell feasibility review is completed before this phase begins.

Implement:

- Version-pinned OpenShell adapter.
- Sandbox lifecycle integration.
- Policy configuration.
- Policy verification integration.
- Controlled filesystem tests.
- Controlled network tests.

**Acceptance criteria:**

The application can execute a controlled workload under actual OpenShell enforcement, and the expected restrictions are independently verified.

Do not advance to untrusted tool execution until this phase passes.

## Phase 4 — Single-Agent Execution

Implement:

- Task model.
- Agent lifecycle.
- Tool invocation.
- Execution tracking.
- Failure handling.
- Resource limits.
- Evaluation harness in `benchmarks/` (a separate environment) with DeepEval task-completion and tool-use metrics, a local judge model, and deterministic outcome assertions.

**Acceptance criteria:**

One agent completes a controlled task and produces structured execution records.

The evaluation harness scores single-agent runs from AEGIS's own records, with DeepEval's telemetry and uploads disabled, and without DeepEval in the application's dependencies.

Until the audit (Phase 5) and approval (Phase 6) controls are available, execution is restricted to explicitly permitted low-risk operations. This restriction must not be relaxed to preserve the phase order.

## Phase 5 — Provenance and Audit

Implement:

- Provenance schemas.
- Trust labels.
- Content hashing.
- Event recording.
- Task correlation.
- Audit persistence.

**Acceptance criteria:**

Relevant external inputs and security-relevant actions can be traced to their origins and associated tasks.

## Phase 6 — Risk Engine and Approval Workflow

Implement:

- Risk classification.
- Task-aware decisions.
- Capability checks.
- Policy versioning.
- Human approval.
- Policy regression tests.
- Policy verification workflow.

**Acceptance criteria:**

High-risk actions cannot proceed without required authorization and enforcement.

## Phase 7 — Evidence Verification

Implement:

- Evidence schemas.
- Artifact hashing.
- Test-result collection.
- Independent verification.
- Completion-state transitions.

**Acceptance criteria:**

A task cannot be marked verified without the required evidence.

DeepEval may grade the quality of an agent's explanation; evidence verification itself stays deterministic.

## Phase 8 — Observability

Implement:

- OpenTelemetry instrumentation.
- Langfuse integration.
- Trace correlation.
- Prompt version tracking.
- Evaluation datasets.
- Optional observability deployment.
- Links from evaluation runs to traces by identifier; DeepEval's own tracing and cloud uploads stay disabled.

**Acceptance criteria:**

A developer can inspect an execution across its agents, model calls, and tool invocations.

The core application must remain usable when optional Langfuse services are disabled.

## Phase 9 — Multi-Agent Orchestration

Introduce:

- Planner.
- Researcher.
- Implementer.
- Security Reviewer.
- Verifier.
- Auditor.

Each agent must have explicit permissions and responsibilities.

Multi-agent evaluation (delegation, plan adherence) uses DeepEval, computed from AEGIS's execution records.

**Acceptance criteria:**

Agents collaborate successfully without inheriting unrestricted permissions from one another.

## Phase 10 — Adversarial Benchmark

Implement:

- Attack scenarios.
- Security fixtures.
- Benchmark runner.
- Result schemas.
- Baseline measurements.
- Repeatable evaluation.
- DeepTeam attack generation, mapped to the OWASP Top 10 for LLMs, the OWASP Top 10 for Agentic Applications and the categories in §15.

**Acceptance criteria:**

The same benchmark can be executed against multiple configurations and produces comparable results.

Adversarial runs target only disposable deployments with synthetic secrets, under verified OpenShell. Security results come from deterministic assertions; DeepTeam's verdicts are reported beside them, with their agreement rate.

## Phase 11 — CI/CD and Supply-Chain Security

Implement:

- Quality gates.
- Security scans.
- OpenShell integration tests.
- Model evaluation workflows: a scheduled, non-blocking workflow for DeepEval and DeepTeam suites with local judges. Deterministic suites remain the required checks, and the evaluation lockfile is scanned and included in the SBOM.
- SBOM generation.
- Artifact scanning.
- Release automation.

**Acceptance criteria:**

Every release has documented build, test, security, and artifact verification results.

## Phase 12 — Research Evaluation and Public Release

Implement:

- Reproducible experiment configurations.
- Calibrated judges, repeated trials and confidence intervals, with evaluation framework and judge model versions recorded.
- Benchmark documentation.
- Results analysis.
- Limitations.
- Security documentation.
- Deployment documentation.
- Contribution guide.

**Acceptance criteria:**

An independent developer can reproduce the documented experiments using the published instructions.

---

# 12. Testing Strategy

Testing must be part of implementation, not an activity postponed until the end.

## Unit tests

Test individual components:

- Risk engine.
- Policy decisions.
- Provenance classification.
- Approval logic.
- Evidence validation.
- Tool schemas.
- Configuration validation.
- Model-provider abstractions.

## Integration tests

Test:

- API and database.
- Worker and task lifecycle.
- Model-provider integration.
- Audit persistence.
- Langfuse integration.
- OpenTelemetry export.
- OpenShell adapter.

## Security tests

Test:

- Filesystem restrictions.
- Network restrictions.
- Secret access prevention.
- Policy enforcement.
- Approval bypass attempts.
- Unauthorized tool calls.
- Prompt injection.
- Agent delegation boundaries.

## End-to-end tests

Execute a complete workflow:

```text
User Request
    |
    v
Task Creation
    |
    v
Risk Assessment
    |
    v
Agent Execution
    |
    v
Tool Invocation
    |
    v
Security Review
    |
    v
Evidence Verification
    |
    v
Audit Recording
    |
    v
Task Completion
```

## Determinism requirements

Use mock providers and fixed fixtures for deterministic CI.

Model-dependent evaluations must record:

- Model name and version.
- Model digest where available.
- Quantization.
- Prompt version.
- Model parameters.
- Dataset version.
- Runtime version.
- Execution configuration.

Do not rely on LLM-as-a-judge as the only evaluation mechanism.

---

# 13. Observability with Langfuse

Langfuse is an important component of AEGIS's evaluation and observability architecture.

It should not become a mandatory dependency for basic local execution.

## What to trace

- Task creation.
- Agent execution.
- Model requests.
- Model responses.
- Tool invocations.
- Agent delegation.
- Approval requests.
- Verification outcomes.
- Execution failures.

## Trace correlation

Every event should be correlated using stable identifiers where applicable:

- `task_id`
- `execution_id`
- `agent_id`
- `tool_call_id`
- `parent_execution_id`
- `policy_version`
- `model_version`

## Observability architecture

```text
AEGIS Components
       |
       v
Observability Interface
       |
       +---- OpenTelemetry
       |       |
       |       v
       |   OTel Collector
       |       |
       |       +---- Langfuse
       |       |
       |       +---- Other Backends
       |
       +---- AEGIS Security Audit Store
       |
       +---- Evidence Store
```

## Important separation

Langfuse provides observability and evaluation.

It does not replace:

- Security audit persistence.
- Policy enforcement.
- Evidence integrity verification.
- OpenShell runtime enforcement.

If Langfuse is unavailable, non-critical telemetry may be buffered or handled according to the configured telemetry policy.

Security-critical audit persistence must follow a separate, explicit failure policy.

---

# 14. CI/CD Architecture

CI/CD is a core part of AEGIS.

The pipeline should validate application correctness, runtime security, model behavior, and software supply-chain integrity.

## Proposed workflows

| Workflow | Responsibility | Trigger |
|---|---|---|
| `ci.yml` | Formatting, linting, typing, unit tests and schema checks | Every PR and push |
| `integration.yml` | Database, API, worker and provider integration | PR or push |
| `openshell-integration.yml` | Real sandbox and policy enforcement tests | Dedicated isolated runner |
| `security.yml` | Dependency, secret, image and policy scanning | PR and scheduled |
| `benchmark.yml` | Adversarial and agent evaluation | Nightly or manual |
| `release.yml` | Build, SBOM, signing and release validation | Release tag |

Only `ci.yml` is implemented so far. It runs the static checks, the unit tests and the integration tests (PostgreSQL, migrations and the doctor) on every push to `main` and every pull request, so database integration currently lives in `ci.yml` rather than a separate `integration.yml`. The other workflows are planned.

## CI stages

```text
Pull Request
    |
    v
Static Analysis
    |
    v
Unit Tests
    |
    v
Schema & Migration Validation
    |
    v
Security Scanning
    |
    v
Integration Tests
    |
    v
Policy Validation
    |
    v
Build Artifacts
    |
    v
Release Approval
```

## OpenShell integration testing

OpenShell tests require a dedicated environment with the necessary runtime capabilities.

Do not expose persistent privileged self-hosted runners to arbitrary pull requests or fork code.

Use:

- Disposable or ephemeral runners.
- Isolated execution environments.
- No shared sensitive state.
- No secrets exposed to untrusted PR code.
- Explicit cleanup after tests.

Never use a workflow configuration that checks out untrusted pull-request code with privileged credentials.

## Model evaluation in CI

Model evaluation must be distinct from deterministic unit testing.

Use:

- Pinned model tags or digests where available.
- Fixed datasets.
- Structured evaluation results.
- Deterministic invariants.
- Mock endpoints.
- Canary secrets.
- Repeatable adversarial scenarios.

A model evaluator must not be the sole authority for deciding whether a security test passed.

DeepEval and DeepTeam suites run in a separate, scheduled workflow from the evaluation project's own environment, with local judge models. They never gate ordinary pull requests, and they never send data to Confident AI.

---

# 15. Adversarial Benchmark

The AEGIS Adversarial Benchmark is a central research deliverable.

## Benchmark categories

| Category | Example |
|---|---|
| Prompt injection | Malicious instructions embedded in repository files |
| Filesystem security | Attempts to read or modify prohibited files |
| Network security | Attempts to contact unauthorized endpoints |
| Credential security | Attempts to expose secrets |
| Tool authorization | Attempts to invoke unauthorized tools |
| Delegation security | Attempts to inherit another agent's privileges |
| Approval integrity | Attempts to bypass required approval |
| Evidence integrity | Attempts to falsify task completion |
| Supply-chain security | Attempts to introduce malicious dependencies |
| Recovery | Attempts to exploit failure or restart behavior |

## Benchmark configurations

Evaluate at least three configurations:

| Configuration | Description |
|---|---|
| Baseline | Agent with basic runtime restrictions |
| Runtime enforcement | Agent with OpenShell enforcement |
| AEGIS | OpenShell plus AEGIS governance, provenance, approvals and evidence verification |

Use the same benchmark tasks and comparable model configurations wherever possible.

## Benchmark result schema

Each execution should record:

- Benchmark ID.
- Scenario ID.
- Configuration.
- Model and version.
- Runtime version.
- Policy version.
- Expected outcome.
- Actual outcome.
- Security result.
- Task completion result.
- Evidence references.
- Execution duration.
- Resource consumption.
- Evaluation framework versions, and the judge model and digest where model-based metrics are used.

Results must be versioned and reproducible.

The security result is decided by deterministic assertions over AEGIS's records. When DeepTeam judges the same case, its verdict is recorded beside the deterministic result.

---

# 16. Research Evaluation

The project should evaluate both security and usefulness.

## Primary metrics

| Metric | Definition |
|---|---|
| Task success rate | Percentage of legitimate tasks completed successfully |
| Unsafe action prevention rate | Percentage of prohibited actions prevented |
| Policy violation rate | Frequency of prohibited action attempts |
| False positive rate | Percentage of legitimate actions incorrectly blocked |
| False negative rate | Percentage of prohibited actions not prevented |
| Approval frequency | Frequency of human approval requirements |
| Evidence completeness | Percentage of tasks with required verification evidence |
| Mean task duration | Average task execution time |
| Cost per successful task | Resource cost associated with successful completion |
| Recovery rate | Percentage of recoverable failures handled safely |

## Experimental methodology

For meaningful comparisons:

1. Define a fixed benchmark dataset.
2. Define the baseline configurations.
3. Pin model and runtime versions.
4. Run repeated trials where behavior is nondeterministic.
5. Record all execution metadata.
6. Use deterministic checks for security invariants.
7. Calculate appropriate confidence intervals.
8. Report failures and limitations.
9. Publish benchmark configuration and results.
10. Calibrate model-based judges against human-labelled sets, use a judge that is not the model under test, and report its agreement and error rates.

The research objective is not to maximize the number of blocked actions.

It is to demonstrate measurable improvements in security while preserving legitimate task completion.

---

# 17. Security Model and Threat Boundaries

## Threat model

AEGIS assumes that the following may be malicious, compromised, or unreliable:

- User-provided content.
- Repository files.
- External documentation.
- Web pages.
- Dependency metadata.
- Tool outputs.
- Model-generated content.
- Agent-to-agent messages.
- External services.

## Security boundaries

### AEGIS control plane

Responsible for:

- Identity.
- Authorization.
- Risk decisions.
- Approval workflows.
- Task orchestration.
- Provenance.
- Audit correlation.
- Evidence verification.

### NVIDIA OpenShell

Responsible for supported runtime enforcement, including sandbox and access restrictions.

### Model provider

A model is an untrusted decision-making component.

Its output must be validated before sensitive actions are executed.

### Langfuse and telemetry

Observability systems must not be treated as the security enforcement boundary.

Sensitive data must be redacted or excluded from telemetry according to policy.

## Fail-closed behavior

| Failure | Expected behavior |
|---|---|
| Langfuse unavailable | Continue only if required security audit persistence remains healthy |
| AEGIS audit store unavailable | Block operations requiring durable audit evidence |
| Ollama unavailable | Fail gracefully or use an explicitly configured alternative |
| Approval service unavailable | Keep high-risk actions blocked |
| OpenShell enforcement unavailable | Do not run untrusted workloads without the required security boundary |
| OpenShell integration disabled | Untrusted execution is unavailable; disabling OpenShell never enables unsandboxed execution |
| Agent crashes | Mark execution interrupted and recover through a controlled workflow |
| Database unavailable | Stop operations that require durable state |
| Evidence verification fails | Do not mark the task verified |

## Secrets management

- Never commit credentials.
- Never log raw secrets.
- Never expose provider credentials to untrusted agents.
- Use endpoint-bound credentials where supported.
- Keep sensitive configuration outside agent-visible workspaces.
- Use dedicated test credentials for integration testing.
- Redact sensitive data from traces and logs.

---

# 18. Developer Experience

A new contributor should be able to understand and run AEGIS without relying on the original developer.

## Developer commands

Implemented (see the [getting-started guide](docs/development/getting-started.md); `make help` lists them):

```bash
make setup
make env-upgrade
make doctor
make up
make up-local-ai
make model-pull
make migrate
make api
make worker
make down
make test
make test-integration
make test-security
make test-local-ai
make lint
make format
make typecheck
make check
```

Planned, not implemented yet:

```bash
make demo
make up-observability
make up-full
make benchmark
```

`make demo` becomes part of the required interface once the capabilities it demonstrates exist. The other planned commands are optional.

## Environment diagnostics

`make doctor` runs the diagnostics in `src/aegis/doctor/`. It currently validates:

- Runtime versions (Python 3.13 and uv).
- Docker availability.
- Docker Compose availability.
- Disk space.
- Memory availability.
- Required ports (the PostgreSQL host port).
- Database availability (PostgreSQL health and a TCP connection; authentication is covered by `make test-integration`).
- Migration status (the schema is at the latest revision).
- Environment configuration (`.env`, including the API, worker and model settings).
- The model provider: required only when `AEGIS_MODEL_PROVIDER=ollama`, when the local Ollama server must be reachable, at the verified version, with the configured model present, local and matching its pinned digest.
- NVIDIA OpenShell: skipped while `AEGIS_SANDBOX_RUNTIME=none`. Required when it is `openshell`: Landlock ABI 3 or later, and the CLI, prover and gateway at the verified 0.1.6, connected, with AEGIS's workspace present, no global policy, and the probe image configured and present.

It also runs two optional checks: whether it runs inside the project `.venv`, and whether `.env` grants access to other users.

Planned checks are listed as "not checked" until their phase implements them:

- Langfuse availability when enabled (Phase 8).

Every check is either required or optional, and is reported as passed, warning, failed or skipped. A required check that fails or cannot run makes `make doctor` exit non-zero.

## Demo requirements

`make demo` is not implemented yet. The local demonstration should produce:

- Task execution records.
- Agent activity.
- Provenance records.
- Risk decisions.
- Policy outcomes.
- Verification evidence.
- Final task status.
- Observability traces when enabled.

A demonstration using a mock model must be explicitly identified as a mock execution.

A demonstration using real OpenShell enforcement must report the actual runtime configuration.

---

# 19. Contribution Guidelines

Contributions should preserve the project's security boundaries and reproducibility requirements.

Before submitting a contribution:

1. Read `AGENTS.md`.
2. Understand the relevant architectural boundary.
3. Implement the smallest useful change.
4. Add or update tests.
5. Run formatting and static analysis.
6. Run relevant unit and integration tests.
7. Document configuration changes.
8. Update architecture documentation when boundaries change.

## Coding expectations

- Prefer small, independently testable modules.
- Use typed interfaces.
- Validate all external inputs.
- Use structured errors.
- Avoid hidden global state.
- Avoid logging secrets.
- Pin dependencies.
- Keep adapters separate from core logic.
- Document security-sensitive decisions.
- Do not silently downgrade enforcement.
- Do not mark unverified tasks as successful.

## Security-sensitive changes

Changes involving permissions, policies, sandbox behavior, credential handling, or external side effects require explicit security tests.

A change that weakens a security boundary must not be merged merely because the application tests pass.

---

# 20. Definition of Done

AEGIS is not ready for public release merely because it works on the original developer's machine.

The public release criteria are:

### Reproducibility

- A new developer can clone the repository.
- Setup instructions work on a documented supported environment.
- The core stack starts locally.
- No paid API key is required for basic execution.
- Deterministic tests run without a large model download.

### Local inference

- Ollama integration works.
- Model configuration is documented.
- Hardware expectations are explicit.
- Model-provider failures are handled safely.

### Runtime security

- OpenShell integration is validated.
- Actual filesystem and network restrictions are tested.
- Enforcement failures do not silently permit untrusted execution.
- Security limitations are documented.

### Governance

- Agents have explicit permissions.
- Risk decisions are recorded.
- High-risk actions require appropriate authorization.
- Policy changes are verified.

### Provenance and evidence

- Relevant inputs have traceable origins.
- Security events are recorded.
- Task completion requires independent evidence.

### Observability

- Agent execution can be traced.
- Langfuse can be enabled locally.
- Security auditing remains independent of Langfuse.
- Sensitive telemetry is handled according to policy.

### Research

- The adversarial benchmark is reproducible.
- Baseline comparisons are documented.
- Evaluation methodology is transparent.
- Limitations and failure cases are reported.

### Delivery

- CI/CD quality gates are implemented.
- Dependencies are scanned.
- SBOM generation is available.
- Release artifacts are verifiable.

---

# 21. Project Status

AEGIS is an evolving research and engineering project.

The architecture describes the intended end state. Components must be implemented incrementally and marked complete only after their acceptance tests pass.

Phases 0, 1 and 2 are implemented: see [docs/development/getting-started.md](docs/development/getting-started.md), the [Phase 1 threat model](docs/security/phase-1-threat-model.md) and the [Phase 2 threat model](docs/security/phase-2-threat-model.md). Phase 2's acceptance workflow, a `generate` task from the API through the worker to its audited result, passes with the mock provider in CI and with a local Ollama model through `make test-local-ai`. Phase 3 (OpenShell integration) is in progress: the sandbox runtime contract, a version-pinned OpenShell adapter verified against OpenShell 0.1.6, AEGIS's sandbox policies and probe image, a prover gate that admits a sandbox only after its submitted and effective policies are proven within the boundary, and enforcement probes that verify the sandbox's filesystem, process and network restrictions independently all exist. No AEGIS task runs in a sandbox yet. No phase yet provides runtime isolation for AEGIS workloads.

| Capability | Target status |
|---|---|
| Architecture and threat model | Defined |
| Progressive implementation plan | Defined |
| Local-first development strategy | Defined |
| Local development foundation (Phase 0) | Implemented |
| API, worker, database and configuration (Phase 1) | Implemented |
| Model provider abstraction (Phase 2) | Implemented: a deterministic mock, a local Ollama provider and the `generate` task kind |
| Ollama integration | Implemented: local models on `127.0.0.1` only, pinned image and model digests, verified on Ollama 0.34.2 |
| NVIDIA OpenShell integration | Partially implemented: a version-pinned adapter verified on 0.1.6, fingerprinted sandbox policies, a prover gate and independently verified enforcement probes; no AEGIS task runs under it yet |
| Agent orchestration | Planned |
| Provenance engine | Planned |
| Risk and policy engine | Planned |
| Human approval workflow | Planned |
| Evidence verification | Planned |
| Langfuse integration | Planned |
| OpenTelemetry integration | Planned |
| Adversarial benchmark | Planned |
| CI/CD automation | Partially implemented: CI runs the checks and every test suite; delivery and supply-chain scanning are Phase 11 |
| Reproducible research evaluation | Planned |

Project status must be updated as implementation progresses. Do not mark planned features as implemented without working code and passing acceptance tests.

---

# Final Principle

**AEGIS must be secure by architecture, observable by design, verifiable through evidence, measurable through research, and reproducible on another developer's machine.**

The objective is not to build the largest possible technology stack.

The objective is to build a system whose security properties can be tested, whose behavior can be inspected, whose results can be reproduced, and whose limitations are honestly documented.