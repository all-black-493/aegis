# ADR-0020: The model step contract

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

Phase 4 needs an agent that takes one step at a time: the model sees a conversation and the tools on offer, and either proposes tool calls or answers in text. The provider contract (ADR-0013) offers only `generate`, a single prompt with no tools, and the Ollama adapter (ADR-0014) refuses tool calls on purpose. That refusal must survive, because `generate` output is inert (ADR-0015).

The step has to work with the deterministic mock in CI and with a local model. A proposal is the first model output AEGIS parses into a structure, so the contract has to keep it bounded and untrusted.

## Behaviour observed on Ollama 0.34.2 with `qwen3:0.6b` (2026-11-06)

| Probe | Observed |
|---|---|
| `POST /api/chat` with `tools`, `stream: true` | Each tool call arrives whole, in its own chunk: `message.tool_calls[0]` is `{"id": "call_…", "function": {"index": n, "name": …, "arguments": {…}}}`. `arguments` is a JSON object, not text. A final empty chunk carries `done: true`, `done_reason: "stop"`, `prompt_eval_count` and `eval_count` |
| Two calls in one reply | Two chunks, with `index` 0 and 1, then the final chunk |
| `num_predict: 3` | Plain text cut short, with `done_reason: "length"` |
| Sending results back | `role: "tool"` with `tool_name` and `content` is accepted, after the assistant's `tool_calls` are replayed without `id` or `index` |
| A direct request naming a file | The model proposes a call, but not reliably as asked: for "Read a.txt." it proposes the path `/a.txt` |
| A goal, with or without a system prompt | "Fix the typo in config.txt", "change the word prot to port" and "create a file named hello.txt" each got a plain-text refusal such as "None of the tools can be used". A simulated loop over three such goals completed none |

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Shape | `aegis.model_providers.steps` defines `Role`, `Message`, `ToolDefinition`, `ToolCall`, `StepRequest` and `StepReply`, and `StepProvider`, which extends `ModelProvider` with `step(request, stop_requested)`. `build_provider` returns a `StepProvider`. A `StepReply` holds an ordinary `Generation` and its proposed calls | `contract.py` stays as it was, and a step's text, counts and identity are validated in one place. |
| Native tool calling | The model is offered tools through Ollama's `tools` field, and replies are parsed from `tool_calls` (decision U3). Text the model writes is never scanned for a call | It suits models built for it and needs no JSON-in-prose parser. Later phases need the same structured form. |
| A proposal is untrusted | A `ToolCall` is a name and arguments, checked only for shape. The provider layer has no registry, policy or execution, and the layering rules keep it that way. Whether a proposal may run is decided elsewhere (Increments 2 and 3) | AGENTS.md §3.4: a model is never the authority for an action. |
| Bounds | A tool name is a lowercase identifier of at most 64 characters. Arguments are a JSON object of at most 8 KiB and 8 levels, with no NaN or infinities. A request has at most 128 messages, 16 tools and 64 KiB; a reply at most 8 calls. Sampling limits are shared with `generate` through `sampling_problems` | A model cannot use a proposal to exhaust memory or to reach a record AEGIS cannot store. |
| Immutability | A `ToolCall` keeps a private copy of its arguments behind a read-only mapping | What is checked is what later code sees. |
| `generate` | Unchanged: one user message, no tools, and a tool call still fails with `tool_call`. The shared streaming code has one hook, and only `StepStream` accepts calls | ADR-0015's guarantee stands. |
| Adapter | `step` makes the same checks as `generate` on every call (ADR-0014) and also requires the `tools` capability, otherwise `no_tools`. The request carries the messages, the tools, `stream: true`, the fixed options and `think: false` when the model reports `thinking`. Never a response format, `keep_alive`, template or raw mode. Replayed calls drop Ollama's `id` and `index` | The checks describe the model that actually answers, and nothing a caller supplies reaches the server beyond the conversation. |
| Failures | A malformed, oversized, over-deep or surplus proposal is a `ProviderProtocolError`, not retried. A stream that ends early, an `error` line or a 5xx is `ProviderUnavailableError`, retried, and no partial proposal is returned. A line too deeply nested for the JSON parser is now a protocol error for `generate` too | Only transient failures repeat. |
| Mock | `MockProvider(script=…)` plans each step. `scripted(...)` picks the step from the number of assistant messages in the request, so the mock holds no state and stays a pure function of the request. Without a script it answers in text, as `generate` does. A script does not affect `generate` | CI can run an agent with no model download (AGENTS.md §6.1). |
| Tests | One contract suite runs against both the mock and a fake Ollama server. `local_ai` tests run a real proposal and result round trip | The two providers cannot drift apart unnoticed. |

## Consequences and limitations

- **No caller yet.** `step` is unused until the agent loop (Increment 4). Only `generate` tasks call a provider so far.
- **`qwen3:0.6b` cannot be assumed to finish a scenario.** It can propose a call, and it can propose the wrong argument, so it satisfies this contract but not yet Phase 4's real-model acceptance. A better prompt or a larger model is a decision for Increment 4, and nothing is downloaded without approval.
- **Models get arguments wrong.** The `/a.txt` proposal above is ordinary behaviour, not an attack. Tools must refuse it or report it back to the model.
- **Prompts grow with history.** A step resends the whole conversation, up to 64 KiB. Trimming it is the agent loop's job.
- **Mock token counts are rough.** A scripted proposal counts one output token per call.
- **Other Ollama versions are unverified,** as in ADR-0014.
