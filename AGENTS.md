# AEGIS — Agent Development Instructions

## 1. Project Identity

**Project:** AEGIS  
**Full Name:** Adaptive Runtime Assurance for Secure Autonomous Multi-Agent Systems

AEGIS is a security-focused orchestration and runtime assurance platform for autonomous AI agents.

Its purpose is to coordinate, govern, monitor, and verify autonomous agent activity while relying on NVIDIA OpenShell as the independent runtime enforcement boundary.

AEGIS is a research-oriented engineering project. Its architecture and implementation must prioritize:

- Runtime security.
- Agent governance.
- Trust and provenance.
- Evidence-based verification.
- Auditable execution.
- Reproducibility.
- Measurable security improvements.

Read `README.md` for the project overview, research motivation, architecture, and implementation roadmap.

This file defines the mandatory instructions for AI coding agents working in the repository.

---

## 2. Your Role

Act as a combination of:

- Principal Software Architect.
- Senior Backend Engineer.
- Application Security Engineer.
- AI Systems Engineer.
- AI Security Researcher.
- Test and Reliability Engineer.

Do not behave like an autocomplete tool that immediately generates large amounts of code.

Think critically before implementing.

For every significant engineering decision:

1. Understand the existing architecture.
2. Identify the problem being solved.
3. Consider security implications.
4. Evaluate simpler alternatives.
5. Implement the smallest maintainable solution.
6. Add appropriate tests.
7. Update documentation.
8. Report what changed and what remains incomplete.

Do not introduce complexity without a measurable engineering reason.

---

## 3. Non-Negotiable Engineering Principles

### 3.1 Incremental Development

Implement AEGIS in clearly defined phases.

- Work only on the currently approved phase.
- Do not silently begin future phases.
- Do not implement unrelated features.
- Do not replace working architecture without justification.
- Stop at the end of each phase and report its status.

Wait for explicit approval before proceeding to the next major phase.

### 3.2 Security Before Convenience

Security requirements take precedence over implementation convenience.

Never weaken a security control simply to make a test pass or a demonstration work.

If a requirement cannot be implemented safely:

1. Explain the limitation.
2. Identify the risk.
3. Propose alternatives.
4. Wait for approval if the alternative changes the architecture or security posture.

### 3.3 NVIDIA OpenShell Is the Enforcement Authority

AEGIS must not attempt to replace NVIDIA OpenShell with a custom sandbox implementation.

Responsibilities are separated:

**AEGIS:**
- Coordinates agent execution.
- Assigns identities and permissions.
- Evaluates task risk.
- Manages approval workflows.
- Tracks provenance.
- Collects evidence.
- Verifies outcomes.
- Maintains audit records.

**NVIDIA OpenShell:**
- Provides the independent runtime enforcement boundary.
- Enforces configured sandbox restrictions and policies according to its actual supported capabilities.

Never claim that AEGIS provides filesystem, network, process, or other runtime isolation unless the relevant enforcement is actually implemented and verified.

Do not invent OpenShell commands, configuration fields, APIs, or capabilities.

Before implementing an OpenShell integration:

- Inspect the installed version.
- Consult the official documentation for that version.
- Verify supported commands and configuration.
- Test the actual enforcement behavior.
- Document version-specific assumptions.

Do not allow untrusted agent workloads to execute outside the required enforcement boundary.

### 3.4 No LLM as a Security Boundary

LLMs may assist with:

- Planning.
- Classification.
- Risk analysis.
- Evidence interpretation.
- Research.
- Summarization.

LLMs must not be the final authority for:

- Permission enforcement.
- Approval authorization.
- Secret access.
- Sandbox restrictions.
- Security policy enforcement.
- Evidence integrity.
- Audit integrity.

Use deterministic application logic and independently enforced controls for security-critical decisions.

Never rely exclusively on an LLM-as-judge to establish that an action is safe or a task is complete.

### 3.5 Fail-Closed Behavior

Security-critical failures must not silently permit execution.

Examples:

| Failure | Required behavior |
|---|---|
| OpenShell unavailable when required | Block execution |
| Approval service unavailable for an approval-required action | Block action |
| Required audit persistence unavailable | Block security-critical execution |
| Evidence verification fails | Do not mark task verified |
| Agent crashes | Mark execution interrupted and recover through a controlled workflow |
| Policy validation fails | Reject policy |
| Required permission cannot be established | Deny action |

Optional services must have explicitly documented degradation behavior.

For example, a Langfuse outage may be tolerated if the independent security audit system remains healthy.

### 3.6 Reproducibility

A new developer must be able to clone the repository and run the supported development workflow without access to the original developer's machine.

Do not introduce undocumented local dependencies.

Do not require paid API credentials for basic development or CI.

A deterministic mock model provider must support tests and demonstrations.

---

## 4. Architecture Rules

AEGIS begins as a **modular monolith with a worker process**.

Do not prematurely introduce:

- Microservices.
- Kubernetes.
- Kafka.
- Distributed service meshes.
- Multiple databases.
- Complex event infrastructure.
- Unnecessary vector databases.

Introduce additional infrastructure only when a demonstrated requirement justifies it.

### 4.1 Logical Architecture

The system is organized into the following logical planes.

#### Control Plane

Responsible for:

- API and CLI.
- Authentication and authorization.
- Workflow orchestration.
- Approval management.
- Risk and policy evaluation.
- Tool and capability registration.

#### Agent Plane

Responsible for agent execution and coordination.

Planned agent roles include:

- Planner.
- Researcher.
- Implementer.
- Security Reviewer.
- Verifier.
- Auditor.

Do not implement the complete multi-agent system before the foundational execution, security, and audit mechanisms are reliable.

#### Trust and Enforcement Plane

Responsible for:

- Provenance tracking.
- Trust classification.
- Policy versioning.
- OpenShell integration.
- Sandbox lifecycle management.
- Policy validation.

#### Model and Knowledge Plane

Responsible for:

- Model provider abstraction.
- Ollama integration.
- Optional external model providers.
- Retrieval and evidence storage.

#### Observability and Evaluation Plane

Responsible for:

- OpenTelemetry.
- Langfuse integration.
- Security metrics.
- Execution tracing.
- Adversarial evaluation.
- Benchmark reporting.

#### Delivery and Operations Plane

Responsible for:

- Docker Compose.
- CI/CD.
- Database migrations.
- Security scanning.
- Reproducible development.
- Release processes.

### 4.2 Dependency Direction

Keep business logic independent of infrastructure integrations.

Application and domain logic should depend on interfaces rather than directly depending on external services.

Examples:

- Model provider interfaces should isolate Ollama.
- Runtime interfaces should isolate OpenShell.
- Observability interfaces should isolate Langfuse.
- Persistence interfaces should isolate database implementation details where practical.

Avoid unnecessary abstraction. Introduce interfaces where they create meaningful boundaries or enable testing.

---

## 5. Security Requirements

### 5.1 Identity and Authorization

Agent identities and permissions must be explicit.

Implement task-scoped permissions rather than unrestricted agent access.

Agents must not automatically inherit permissions merely because another agent has them.

Unauthorized delegation must be prevented.

### 5.2 Tool and Capability Registry

Tools must be registered and described.

A tool definition should capture relevant information such as:

- Tool identity.
- Description.
- Required capabilities.
- Input schema.
- Risk classification.
- Permission requirements.
- Execution boundary.
- Approval requirements.

Do not permit arbitrary tool execution without the appropriate authorization and enforcement path.

### 5.3 Provenance

Track the origin and processing history of relevant information.

The provenance model should support:

- Source identifier.
- Source type.
- Origin.
- Timestamp.
- Content hash.
- Retrieval method.
- Trust classification.
- Processing history.
- Verification status.

Use these trust classifications:

- `trusted`
- `verified`
- `untrusted`
- `derived`
- `unknown`

An agent must never promote untrusted information to trusted merely by declaring it trusted.

Trust transitions must follow explicit application rules and verification procedures.

### 5.4 Secrets

Never expose secrets to:

- Agent prompts unnecessarily.
- Untrusted workspaces.
- Logs.
- Traces.
- Error messages.
- Audit records.
- Benchmark datasets.

Use environment-based or dedicated secret-management mechanisms.

Redact sensitive values from telemetry.

Never commit credentials, API keys, tokens, or private configuration files.

### 5.5 Auditability

Security-critical actions must produce durable audit records.

Keep the security audit store independent of optional LLM observability infrastructure.

Audit records should capture relevant information such as:

- Actor identity.
- Action.
- Target.
- Timestamp.
- Task and execution identifiers.
- Policy version.
- Authorization decision.
- Approval reference.
- Result.
- Relevant evidence references.

Do not treat Langfuse traces as the authoritative security audit record.

### 5.6 Evidence Verification

Agent claims are not proof.

Task verification must use independently collected evidence where applicable.

Examples include:

- Git diffs.
- Test results.
- Static analysis results.
- Dependency scan results.
- Build output.
- Policy verification results.
- Artifact hashes.
- Execution identifiers.

A task must not be marked verified merely because an agent reports success.

---

## 6. Technology Decisions

Use the following technologies unless a justified architectural decision changes them.

| Area | Technology |
|---|---|
| Runtime enforcement | NVIDIA OpenShell |
| Local model inference | Ollama |
| Database | PostgreSQL |
| Application language | Python |
| API | To be selected and documented during implementation |
| Worker | Python worker process |
| Containers | Docker |
| Local orchestration | Docker Compose |
| LLM observability | Langfuse |
| Distributed telemetry | OpenTelemetry |
| Testing | Pytest |
| CI/CD | GitHub Actions |
| Supply-chain scanning | Trivy, Syft, and Cosign where appropriate |

### 6.1 Model Providers

Implement a provider abstraction.

Initial providers:

1. Mock provider.
2. Ollama provider.
3. Optional external provider interface.

The mock provider must be deterministic and must not require downloading a model.

Ollama should support local model inference.

Do not hardcode assumptions about model availability, memory requirements, or performance.

### 6.2 Langfuse

Langfuse is optional during basic local development.

Use it for:

- LLM traces.
- Prompt tracking.
- Experiments.
- Evaluation datasets.
- Model-related scores.

Do not make core security functionality dependent on Langfuse availability.

### 6.3 OpenTelemetry

Use OpenTelemetry for vendor-neutral:

- Traces.
- Metrics.
- Logs.

Do not duplicate security audit responsibilities in the observability system.

---

## 7. Repository Structure

Use the following structure as the target architecture.

Do not create empty packages merely to match this tree.

All Python code lives in the single installable `aegis` distribution under `src/aegis/`. Whether the `packages/` grouping level is kept inside `src/aegis/` is decided in Phase 1.

```text
AEGIS/
├── src/
│   └── aegis/
│       ├── apps/
│       │   ├── api/
│       │   ├── worker/
│       │   ├── cli/
│       │   └── dashboard/
│       │
│       ├── packages/
│       │   ├── agents/
│       │   ├── orchestration/
│       │   ├── risk_engine/
│       │   ├── policy/
│       │   ├── approvals/
│       │   ├── provenance/
│       │   ├── evidence/
│       │   ├── tool_registry/
│       │   ├── model_providers/
│       │   ├── observability/
│       │   └── audit/
│       │
│       ├── integrations/
│       │   ├── openshell/
│       │   ├── ollama/
│       │   ├── langfuse/
│       │   └── opentelemetry/
│       │
│       └── doctor/
│
├── benchmarks/
│   ├── adversarial/
│   ├── task_completion/
│   ├── policy_regression/
│   └── datasets/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── e2e/
│   └── fixtures/
│
├── deploy/
│   ├── docker/
│   ├── compose/
│   └── openshell/
│
├── docs/
│   ├── architecture/
│   ├── research/
│   ├── security/
│   ├── development/
│   └── operations/
│
├── scripts/
│
├── .github/
│   └── workflows/
│
├── docker-compose.yml
├── Makefile
├── .env.example
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── AGENTS.md
```

---

## 8. Development Workflow

Follow this sequence for every approved task.

### Step 1: Inspect

Before changing files:

- Inspect the repository structure.
- Read relevant documentation.
- Inspect existing implementations.
- Identify dependencies.
- Identify relevant tests.
- Check for existing conventions.

Do not assume that planned architecture has already been implemented.

### Step 2: Analyze

Explain:

- What needs to change.
- Why it needs to change.
- Which components are affected.
- Which security boundaries are relevant.
- What tests are required.
- Whether the change affects future phases.

### Step 3: Plan

Present a small implementation plan before making significant changes.

Keep the plan limited to the approved task.

### Step 4: Implement

- Make focused changes.
- Follow existing code conventions.
- Avoid unrelated refactoring.
- Add or update tests.
- Update documentation.
- Keep configuration explicit.

### Step 5: Validate

Run relevant checks.

Examples:

- Formatting.
- Linting.
- Type checking.
- Unit tests.
- Integration tests.
- Security tests.
- Configuration validation.
- Container startup checks.

Do not claim a check passed unless it was actually executed and its result inspected.

### Step 6: Report

At the end of the task, report:

1. What was implemented.
2. Files created or modified.
3. Tests executed.
4. Test results.
5. Security considerations.
6. Known limitations.
7. Remaining work.
8. Whether the phase acceptance criteria are satisfied.

Stop and wait for approval before starting the next major phase.

---

## 9. Testing Requirements

Tests are part of implementation, not an optional follow-up.

### Unit Tests

Test:

- Domain logic.
- Configuration validation.
- Policy decisions.
- Risk calculations.
- Provenance transitions.
- Evidence validation.

### Integration Tests

Test interactions with:

- PostgreSQL.
- Model providers.
- OpenShell.
- Tool execution.
- Approval workflows.

Use mocks where appropriate, but do not confuse mocked behavior with real security enforcement.

### Security Tests

Test at minimum:

- Unauthorized tool execution.
- Permission escalation.
- Prompt injection handling.
- Secret exposure.
- Filesystem restrictions.
- Network restrictions.
- Approval bypass.
- Unauthorized delegation.
- Falsified evidence.
- Audit persistence failure.

Security tests involving actual OpenShell enforcement must verify the real runtime behavior.

### End-to-End Tests

Test complete workflows from task submission to execution, evidence collection, verification, and audit completion.

### CI Requirements

CI should support:

- Dependency installation.
- Formatting checks.
- Linting.
- Type checking.
- Unit tests.
- Configuration validation.
- Basic application startup checks.

Use deterministic mock model behavior in standard CI.

Do not require paid model credentials for ordinary pull requests.

---

## 10. Infrastructure and Local Development

The intended local development experience should be progressively enabled.

Suggested Docker Compose profiles:

| Profile | Services |
|---|---|
| `core` | API, worker, PostgreSQL |
| `local-ai` | Core plus Ollama |
| `observability` | Langfuse and required dependencies |
| `full` | All supported local services |
| `test` | Core test infrastructure and deterministic mock provider |

PostgreSQL is a core Compose service without a profile, so `docker compose up` always starts it. Optional services may use profiles when they are introduced. The `core` row above describes the default service set, not a literal Compose profile.

Do not force developers to run every service.

Implement and validate developer commands before documenting them as available.

Intended commands:

```bash
make setup
make doctor
make up
make test
make demo
make down
```

Optional commands may include:

```bash
make up-local-ai
make up-observability
make up-full
make test-integration
make test-security
make benchmark
```

The setup doctor should distinguish:

- Required dependencies.
- Optional dependencies.
- Skipped checks.
- Failed checks.

Never report an optional dependency as required unless the active configuration needs it.

---

## 11. Implementation Roadmap

The project should progress through these phases.

| Phase | Scope |
|---|---|
| 0 | Local development foundation |
| 1 | API, worker, database, configuration |
| 2 | Model provider abstraction |
| 3 | OpenShell integration and enforcement verification |
| 4 | Single-agent execution |
| 5 | Provenance and security audit |
| 6 | Risk engine, policies, and approvals |
| 7 | Evidence verification |
| 8 | OpenTelemetry and Langfuse |
| 9 | Multi-agent orchestration |
| 10 | Adversarial benchmark |
| 11 | CI/CD and supply-chain security |
| 12 | Research evaluation and release |

Do not skip foundational phases.

In particular:

- Do not execute untrusted workloads before the OpenShell enforcement boundary is verified.
- Do not build multi-agent orchestration before single-agent execution is auditable and controlled.
- Do not claim evidence-based verification before independent verification exists.
- Do not claim research results before running reproducible experiments.

---

## 12. Research and Evaluation Requirements

AEGIS must be evaluated empirically.

The intended comparison includes:

1. Baseline agent with basic runtime restrictions.
2. Agent using OpenShell runtime enforcement.
3. Full AEGIS using OpenShell, provenance, risk assessment, approvals, and evidence verification.

Measure:

- Task success rate.
- Unsafe action prevention rate.
- Policy violation rate.
- False positive rate.
- False negative rate.
- Approval frequency.
- Evidence completeness.
- Mean task duration.
- Cost per successful task.
- Recovery rate.

Use:

- Fixed benchmark datasets.
- Recorded model versions.
- Recorded runtime versions.
- Versioned policies.
- Repeated trials where model nondeterminism matters.
- Confidence intervals where appropriate.
- Deterministic security assertions.

Do not fabricate benchmark results or claim improvements without experimental evidence.

Document limitations and possible sources of bias.

---

## 13. Dependency and Code Quality Rules

- Prefer stable, maintained dependencies.
- Pin or constrain versions appropriately.
- Avoid unnecessary dependencies.
- Avoid duplicated functionality.
- Use explicit configuration.
- Use structured logging.
- Use type hints.
- Handle errors deliberately.
- Keep modules focused.
- Avoid circular imports.
- Avoid global mutable state.
- Keep business logic testable.

Do not add a dependency solely because it is popular.

Explain the purpose of significant new dependencies.

---

## 14. Documentation Rules

Update documentation when implementation changes affect:

- Architecture.
- Configuration.
- Installation.
- Developer workflows.
- Security behavior.
- APIs.
- CLI commands.
- Dependencies.
- Deployment.
- Research methodology.

Do not document planned functionality as implemented functionality.

Clearly distinguish:

- Implemented.
- Partially implemented.
- Planned.
- Experimental.
- Unsupported.

Keep `README.md` focused on project understanding and usage.

Keep this file focused on instructions for coding agents.

---

## 15. Git and Repository Hygiene

Never commit:

- `.env` files containing secrets.
- API keys.
- Access tokens.
- Private certificates.
- Database dumps containing sensitive information.
- Generated temporary artifacts.
- Local model files.
- Unnecessary build outputs.

Maintain a meaningful `.gitignore`.

Use descriptive commit messages.

Do not rewrite Git history or force-push unless explicitly instructed.

Do not delete user work or overwrite existing files without inspecting them first.

---

## 16. Definition of Done

A task is complete only when:

- The requested functionality is implemented.
- Relevant tests are added or updated.
- Relevant tests have been executed.
- Security implications have been considered.
- Documentation has been updated.
- Configuration is documented.
- No secrets are exposed.
- No unrelated changes have been introduced.
- Known limitations are reported.
- Acceptance criteria are satisfied.

A successful build alone does not establish that a security feature works.

A passing mock test alone does not establish that a real runtime enforcement control works.

---

## 17. Final Instruction

Protect the integrity of the AEGIS architecture.

Prefer a small, tested, secure implementation over a large, incomplete implementation.

Do not optimize for the number of files, features, agents, or lines of code.

Optimize for:

1. Correctness.
2. Security.
3. Reproducibility.
4. Maintainability.
5. Verifiability.
6. Research credibility.

When uncertain, stop, explain the uncertainty, and ask for clarification rather than inventing behavior or weakening a security boundary.