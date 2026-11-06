from aegis.model_providers.steps import Message, Role, StepRequest, ToolCall, ToolDefinition

READ_FILE = ToolDefinition(
    "read_file",
    "Read one file from the workspace.",
    {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
)
WRITE_FILE = ToolDefinition(
    "write_file",
    "Replace one file in the workspace.",
    {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    },
)
READ_A = ToolCall("read_file", {"path": "a.txt"})
WRITE_B = ToolCall("write_file", {"path": "b.txt", "content": "beta"})
SYSTEM = Message(Role.SYSTEM, "You work in a file workspace.")
GOAL = Message(Role.USER, "Read a.txt.")


def step_request(*messages: Message, tokens: int = 64) -> StepRequest:
    return StepRequest(messages or (SYSTEM, GOAL), (READ_FILE, WRITE_FILE), tokens)


def following_a_proposal() -> StepRequest:
    return step_request(
        SYSTEM,
        GOAL,
        Message(Role.ASSISTANT, "", (READ_A,)),
        Message(Role.TOOL, "alpha", tool_name="read_file"),
    )
