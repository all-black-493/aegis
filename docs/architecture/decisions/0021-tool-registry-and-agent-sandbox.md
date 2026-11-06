# ADR-0021: The tool registry and the agent sandbox

- **Status:** Accepted
- **Date:** 2026-11-07

## Context

Phase 4 lets a model propose actions. Until the audit and approval controls of Phases 5 and 6 exist, only explicitly permitted low-risk operations may run, and nothing may run outside OpenShell (README §11). This ADR covers what a tool is and where it runs. Whether a proposed call is allowed is decided by policy, in Increment 3. The agent loop that uses both arrives in Increment 4.

AEGIS's first sandbox policy was written for the probes and carries a network rule for the canary. An agent needs less than that.

## Behaviour observed on OpenShell 0.1.7 (2026-11-07)

| Probe | Observed |
|---|---|
| `sandbox exec` with hostile arguments | Arguments arrive literally. `$(…)`, backticks, `;`, `\|`, globs, quotes, backslashes, newlines and a leading `-` all reached the program unchanged, nothing ran, and a 4 KiB argument works. A fixed `bash -c` script reading `"$1"` treats the text as data |
| A policy with no `network_policies` | Accepted. The effective policy is the submitted one, with no baseline path added, and it is `within_boundary` |
| The probe policy against the agent boundary | `exceeds_boundary`, so a network rule cannot pass this gate |
| Writing outside the workspace | `Permission denied`, including under `/tmp`, because the agent policy doesn't list it |
| Reading outside the policy | `Permission denied` for `/srv/aegis/unlisted` and `/srv/aegis/readonly`, also through `..` |
| A symlink out of the workspace | Creating it succeeds, because only the link's own directory matters. Reading through it to an unlisted path is refused by Landlock. Reading through it to a listed path such as `/etc/passwd` succeeds, so AEGIS has to refuse that itself |
| Any connection | `connect()` fails with `EACCES`, and AEGIS's canary sees nothing |

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Registry | `aegis.tool_registry` is closed and defined in code, like the task handlers. `TOOLS` is read-only. Each `RegisteredTool` holds its name and version, description, input and output schemas, capabilities, risk, side-effect and network classes, limits, approval requirement, permitted roles and execution boundary | AGENTS.md §5.2. A tool cannot appear at run time or be added by configuration. |
| Tools | `list_files`, `read_file` and `write_file`, all confined to the workspace (decision U4). All are low risk, need no network and need no approval. There is no command execution | These are the low-risk operations the README allows before Phases 5 and 6. |
| One way to run | `ToolRunner` is the only path to a tool. It takes an `AdmittedSandbox`, which only `SandboxGate.open` hands out, and refuses any profile but `agent` (`wrong_profile`) | A tool cannot run outside the gate, or in a sandbox with a network rule. |
| Fixed commands | Each tool is a fixed command. Proposed text reaches it only as separate arguments, after the script. No shell is built from model text. The behaviour above is what makes this safe, and a live test keeps checking it | A prompt injection can change a file in the workspace, not what runs. |
| Arguments | `check_arguments` applies the schema's subset: unknown or missing keys, non-strings, NUL and oversized values are refused (`invalid_arguments`). Sizes count UTF-8 bytes. No JSON Schema dependency is added | Fewer moving parts decide what may run. |
| Paths | `workspace_path` accepts only relative, already-normal paths of `[A-Za-z0-9._-]` segments, at most 256 bytes and 8 segments (`path_not_allowed`). Nothing else is rewritten or guessed at, so `/a.txt` is refused, not corrected | The local model does propose `/a.txt` (ADR-0020). Refusing tells it so; correcting would hide it. |
| Symlinks | The fixed scripts run `realpath` inside the sandbox and refuse anything that resolves outside the workspace (`outside_workspace`). A dangling link reads as `not_found` and is refused on write | Landlock can't help when a link points at a listed path. |
| Three layers | A hostile path must get past the argument check, the script's own check, and then Landlock. The live tests go past AEGIS's checks with raw exec to show that OpenShell refuses by itself | AGENTS.md §3.3: AEGIS's checks are not the enforcement boundary. |
| Results | A `ToolResult` has a status (`ok`, `refused`, `failed`) and a stable code. A refused call runs nothing. Runtime errors propagate, so the agent loop can retry them | The model gets a usable reason, and nothing failing looks like success. |
| Limits | 15 s per tool and 8 KiB of output. `list_files` returns at most 256 names. `write_file` takes at most 4 KiB, one exec argument. Cut output says so | Bounds what reaches the model and the records. |
| Sandbox profiles | A `SandboxProfile` names a policy and its boundary. `probe` keeps `probe.yaml` and `boundary.yaml`. `agent` is new: `agent.yaml` and `agent-boundary.yaml`, with no network rules. The gate proves whichever it was given, and `sandbox.created` records the `profile` | An agent gets only what it needs, and its boundary can't be widened by the probes' needs. |
| Workspace | `/srv/aegis/workspace` is the only writable path, and `/srv/aegis/scenarios` is read-only. `/tmp` isn't listed | Everything an agent changes is in one place, ready to be hashed. |
| Image | Release 3 of the image adds the workspace and three scenario fixtures: `fix-config-typo`, `create-greeting` and `copy-note`. They're written by the Dockerfile, so the sandbox policy fingerprint covers them. One image serves both profiles. Policy version `2026.11.07-1` | Scenarios stay fixed and reviewed (decision U2), and one image means one setting. |
| Layering | `aegis.tool_registry` may not import AEGIS's state or decisions, nor any integration, and `aegis.policy` and `aegis.authorization` may not import it. `tests/unit/test_layering.py` enforces this | Tools describe and run; policy decides. |

## Consequences and limitations

- **Nothing calls a tool yet.** `ToolRunner` has no caller until Increment 4, and no tool call is authorized or recorded until Increment 3.
- **`sandbox exec` is the only interface.** Literal arguments are a property of the CLI, so each new OpenShell release must keep passing the live test.
- **An older image is refused.** After this change an `AEGIS_OPENSHELL_IMAGE` from release 2 fails with `image_unrecognised` until `make openshell-image` is run again.
- **`write_file` is capped at 4 KiB,** because content travels as one exec argument.
- **Non-UTF-8 files read lossily.** Fixtures are text, and scenarios are AEGIS's own.
- **The workspace can be filled.** A sandbox's disk use isn't limited here. The agent loop's step limits bound how much can be written.
- **Paths are narrow on purpose.** Spaces and non-ASCII names are refused, even where they'd be harmless.
