import http.client
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from aegis.config.settings import MODEL_HOST, OllamaSettings
from aegis.model_providers.contract import (
    MAX_OUTPUT_BYTES,
    RUNTIME_VERSION,
    FinishReason,
    Generation,
    GenerationRequest,
    GenerationStoppedError,
    InvalidGenerationError,
    ModelIdentity,
    ModelProviderError,
    ModelUnavailableError,
    ProviderProtocolError,
    ProviderStatus,
    ProviderUnavailableError,
    StopCheck,
    bounded_text,
)
from aegis.model_providers.steps import (
    MAX_STEP_TOOL_CALLS,
    Message,
    StepReply,
    StepRequest,
    ToolCall,
)

PROVIDER = "ollama"
VERIFIED_VERSION = "0.34.2"
PULL_READ_TIMEOUT_SECONDS = 300
METADATA_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_STREAM_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class _Model:
    identity: ModelIdentity
    thinking: bool
    tools: bool


class OllamaProvider:
    def __init__(self, settings: OllamaSettings, timeout_seconds: float) -> None:
        self._settings = settings
        self._timeout = timeout_seconds

    def check(self) -> ProviderStatus:
        try:
            model = self._inspect()
        except ModelProviderError as error:
            return ProviderStatus(healthy=False, detail=error.code)
        return ProviderStatus(healthy=True, detail="ok", identity=model.identity)

    def generate(self, request: GenerationRequest, stop_requested: StopCheck) -> Generation:
        model = self._ready(stop_requested)
        stream = ChatStream()
        body = chat_body(self._settings.model, request, thinking=model.thinking)
        duration_ms = self._stream(body, stream, stop_requested)
        return stream.result(model.identity, duration_ms)

    def step(self, request: StepRequest, stop_requested: StopCheck) -> StepReply:
        model = self._ready(stop_requested)
        if not model.tools:
            raise ModelUnavailableError("the model cannot call tools", code="no_tools")
        stream = StepStream()
        body = step_body(self._settings.model, request, thinking=model.thinking)
        duration_ms = self._stream(body, stream, stop_requested)
        return StepReply(stream.result(model.identity, duration_ms), stream.tool_calls)

    def _ready(self, stop_requested: StopCheck) -> _Model:
        if stop_requested():
            raise GenerationStoppedError("generation stopped on request")
        # Re-inspected on every call, so the recorded identity and the locality and digest checks
        # always describe the model that actually answered.
        return self._inspect()

    def _stream(
        self, body: Mapping[str, Any], stream: "ChatStream", stop_requested: StopCheck
    ) -> int:
        started = time.monotonic()
        connection = http.client.HTTPConnection(
            MODEL_HOST, self._settings.port, timeout=self._timeout
        )
        try:
            response = _send(connection, "POST", "/api/chat", body)
            received = 0
            while True:
                if stop_requested():
                    raise GenerationStoppedError("generation stopped on request")
                line = response.readline(MAX_LINE_BYTES + 1)
                if not line:
                    raise ProviderUnavailableError("the model stream ended early")
                received += len(line)
                if len(line) > MAX_LINE_BYTES or received > MAX_STREAM_BYTES:
                    raise ProviderProtocolError("the model stream exceeded its size limits")
                if line.strip() and stream.feed(_object(line)):
                    break
        except (OSError, http.client.HTTPException):
            raise ProviderUnavailableError("the model server could not be reached") from None
        finally:
            # Closing the connection is also how a stopped or cut-off generation ends early.
            connection.close()
        return round((time.monotonic() - started) * 1000)

    def _inspect(self) -> _Model:
        name = self._settings.model
        version = self._fetch("GET", "/api/version").get("version")
        if not isinstance(version, str) or not RUNTIME_VERSION.fullmatch(version):
            raise ProviderProtocolError("the runtime version is malformed")
        show = self._fetch("POST", "/api/show", {"model": name})
        if _remote(show):
            raise ModelUnavailableError("remote-backed models are refused", code="remote_model")
        capabilities = show.get("capabilities")
        if not isinstance(capabilities, list) or "completion" not in capabilities:
            raise ModelUnavailableError("the model cannot generate text", code="not_generative")
        models = self._fetch("GET", "/api/tags").get("models")
        if not isinstance(models, list):
            raise ProviderProtocolError("the model list is malformed")
        entry = next(
            (m for m in models if isinstance(m, Mapping) and same_model(m.get("name"), name)),
            None,
        )
        if entry is None:
            raise ModelUnavailableError("the model is not present locally", code="model_missing")
        if _remote(entry):
            raise ModelUnavailableError("remote-backed models are refused", code="remote_model")
        digest = entry.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ProviderProtocolError("the model digest is malformed")
        if self._settings.digest is not None and digest != self._settings.digest:
            raise ModelUnavailableError(
                "the model digest is not the pinned one", code="digest_mismatch"
            )
        identity = ModelIdentity(PROVIDER, name, digest, version)
        return _Model(identity, "thinking" in capabilities, "tools" in capabilities)

    def _fetch(
        self, method: str, path: str, body: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        connection = http.client.HTTPConnection(
            MODEL_HOST, self._settings.port, timeout=min(METADATA_TIMEOUT_SECONDS, self._timeout)
        )
        try:
            raw = _send(connection, method, path, body).read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException):
            raise ProviderUnavailableError(
                "the model server could not be reached", code="unreachable"
            ) from None
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProviderProtocolError("a model server response exceeded its size limit")
        return _object(raw)


def pull_model(settings: OllamaSettings, report: Callable[[str], None]) -> None:
    # Administration only: the worker never pulls. Ollama reports failures inside the stream.
    connection = http.client.HTTPConnection(
        MODEL_HOST, settings.port, timeout=PULL_READ_TIMEOUT_SECONDS
    )
    try:
        response = _send(connection, "POST", "/api/pull", {"model": settings.model, "stream": True})
        last = None
        while True:
            line = response.readline(MAX_LINE_BYTES + 1)
            if not line:
                raise ProviderUnavailableError("the pull ended before it succeeded")
            if len(line) > MAX_LINE_BYTES:
                raise ProviderProtocolError("the pull stream exceeded its size limits")
            if not line.strip():
                continue
            update = _object(line)
            if "error" in update:
                raise ModelUnavailableError("Ollama could not pull the model", code="pull_failed")
            status = update.get("status")
            if isinstance(status, str) and status != last:
                last = status
                report("".join(c for c in status[:80] if c.isprintable()))
            if status == "success":
                return
    except (OSError, http.client.HTTPException):
        raise ProviderUnavailableError(
            "the model server could not be reached", code="unreachable"
        ) from None
    finally:
        connection.close()


class ChatStream:
    def __init__(self) -> None:
        self._parts: list[str] = []
        self._bytes = 0
        self._reason: str | None = None
        self._prompt_tokens = 0
        self._output_tokens = 0
        self._limited = False

    def feed(self, chunk: Mapping[str, Any]) -> bool:
        if "error" in chunk:
            raise ProviderUnavailableError("the model server reported an error mid-stream")
        if _remote(chunk):
            raise ModelUnavailableError("remote-backed models are refused", code="remote_model")
        message = chunk.get("message", {})
        if not isinstance(message, Mapping):
            raise ProviderProtocolError("a streamed message is malformed")
        self._take_tool_calls(message.get("tool_calls"))
        content = message.get("content", "")
        if not isinstance(content, str):
            raise ProviderProtocolError("a streamed message is malformed")
        if content:
            try:
                self._bytes += len(content.encode())
            except UnicodeEncodeError:
                raise ProviderProtocolError("a streamed message is not valid text") from None
            self._parts.append(content)
            if self._bytes > MAX_OUTPUT_BYTES:
                self._limited = True
                return True
        if chunk.get("done") is not True:
            return False
        reason = chunk.get("done_reason")
        if reason not in (FinishReason.STOP, FinishReason.LENGTH):
            raise ProviderProtocolError("the model stream finished for an unexpected reason")
        self._reason = reason
        self._prompt_tokens = _count(chunk.get("prompt_eval_count", 0))
        self._output_tokens = _count(chunk.get("eval_count", 0))
        return True

    def _take_tool_calls(self, calls: object) -> None:
        if calls:
            raise ProviderProtocolError("the model attempted a tool call", code="tool_call")

    def result(self, identity: ModelIdentity, duration_ms: int) -> Generation:
        text, cut = bounded_text("".join(self._parts))
        if self._limited or cut or self._reason is None:
            # Cut off before the final line, so Ollama sent no counts: streamed chunks stand in.
            return Generation(text, FinishReason.LIMIT, 0, len(self._parts), duration_ms, identity)
        return Generation(
            text,
            FinishReason(self._reason),
            self._prompt_tokens,
            self._output_tokens,
            duration_ms,
            identity,
        )


class StepStream(ChatStream):
    # 0.34.2 streams each tool call whole, in its own chunk, before the final line (ADR-0020).
    def __init__(self) -> None:
        super().__init__()
        self.tool_calls: tuple[ToolCall, ...] = ()

    def _take_tool_calls(self, calls: object) -> None:
        if not calls:
            return
        if not isinstance(calls, list):
            raise ProviderProtocolError("a tool call is malformed")
        self.tool_calls = (*self.tool_calls, *(parse_tool_call(call) for call in calls))
        if len(self.tool_calls) > MAX_STEP_TOOL_CALLS:
            raise ProviderProtocolError("the model proposed too many tool calls")


def parse_tool_call(call: object) -> ToolCall:
    function = call.get("function") if isinstance(call, Mapping) else None
    if not isinstance(function, Mapping):
        raise ProviderProtocolError("a tool call is malformed")
    try:
        return ToolCall(function.get("name"), function.get("arguments"))  # type: ignore[arg-type]
    except InvalidGenerationError:
        raise ProviderProtocolError("a tool call is malformed") from None


def chat_body(model: str, request: GenerationRequest, *, thinking: bool) -> dict[str, Any]:
    # One user message and fixed options only: never tools, a response format or a system prompt.
    messages = [{"role": "user", "content": request.prompt}]
    return _body(
        model, messages, request.temperature, request.seed, request.max_output_tokens, thinking
    )


def step_body(model: str, request: StepRequest, *, thinking: bool) -> dict[str, Any]:
    # The conversation, the offered tools and fixed options only: never a response format.
    messages = [_message(message) for message in request.messages]
    body = _body(
        model, messages, request.temperature, request.seed, request.max_output_tokens, thinking
    )
    body["tools"] = [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": dict(tool.parameters),
            },
        }
        for tool in request.tools
    ]
    return body


def _body(
    model: str,
    messages: list[dict[str, Any]],
    temperature: float,
    seed: int,
    max_output_tokens: int,
    thinking: bool,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": True,
        "options": {"temperature": temperature, "seed": seed, "num_predict": max_output_tokens},
    }
    if thinking:
        body["think"] = False
    return body


def _message(message: Message) -> dict[str, Any]:
    wire: dict[str, Any] = {"role": message.role.value, "content": message.content}
    if message.tool_calls:
        wire["tool_calls"] = [
            {"function": {"name": call.name, "arguments": dict(call.arguments)}}
            for call in message.tool_calls
        ]
    if message.tool_name is not None:
        wire["tool_name"] = message.tool_name
    return wire


def same_model(listed: object, configured: str) -> bool:
    return isinstance(listed, str) and _canonical(listed) == _canonical(configured)


def _canonical(name: str) -> str:
    name = name.removeprefix("library/")
    return name if ":" in name else f"{name}:latest"


def _send(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    body: Mapping[str, Any] | None = None,
) -> http.client.HTTPResponse:
    payload = None if body is None else json.dumps(body).encode()
    headers = {} if payload is None else {"Content-Type": "application/json"}
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    if response.status == 200:
        return response
    if response.status == 404 and path != "/api/version":
        raise ModelUnavailableError("the model is not present locally", code="model_missing")
    if response.status >= 500:
        raise ProviderUnavailableError(f"the model server answered {response.status}")
    raise ProviderProtocolError(f"the model server answered {response.status}")


def _object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ProviderProtocolError("the model server sent malformed JSON") from None
    if not isinstance(value, dict):
        raise ProviderProtocolError("the model server sent malformed JSON")
    return value


def _remote(entry: Mapping[str, Any]) -> bool:
    return bool(entry.get("remote_host") or entry.get("remote_model"))


def _count(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ProviderProtocolError("the model server sent a malformed token count")
