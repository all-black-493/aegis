import json
import os
import sys
from pathlib import Path
from typing import Any

from aegis.config.settings import OpenShellSettings
from aegis.integrations.openshell.cli import OpenShellCli
from aegis.integrations.openshell.runtime import OpenShellRuntime

# The fake is a real executable, so tests exercise the adapter's subprocess path, scrubbed
# environment and argument lists. It reads its behaviour from state.json beside itself, because
# the adapter passes it no environment to configure it with, and records every call.
SCRIPT = r"""
import json
import os
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = HERE / "state.json"


def save(state):
    STATE.write_text(json.dumps(state))


def fail(message, code=1):
    sys.stderr.write("Error:   x " + message + "\n")
    sys.exit(code)


def record(sandbox):
    return {
        "id": sandbox["id"],
        "name": sandbox["name"],
        "phase": sandbox["phase"],
        "labels": sandbox["labels"],
        "workspace": sandbox["workspace"],
        "configuration_admission": {"state": sandbox["admission"], "policy_hash": "ab" * 32},
    }


def option(args, name, default=None):
    return args[args.index(name) + 1] if name in args else default


def prover(state, args):
    if args == ["--version"]:
        print("openshell-prover " + state["prover_version"])
        return
    state["proven"].append(Path(args[1]).read_text())
    sequence = state["verdict_sequence"]
    verdict = dict(sequence.pop(0) if sequence else state["verdict"])
    save(state)
    verdict.setdefault("schema_version", 1)
    verdict.setdefault("prover_version", state["prover_version"])
    print(json.dumps(verdict))
    sys.exit(state.get("prover_exit", verdict.get("exit_code", 0)))


def openshell(state, args):
    if args == ["--version"]:
        print("openshell " + state["version"])
        return
    scope = {}
    while args and args[0] in ("--gateway", "--workspace", "--color"):
        scope[args[0]] = args[1]
        args = args[2:]
    workspace = scope.get("--workspace", "default")
    command, rest = args[:2], args[2:]
    sandboxes = state["sandboxes"]
    if args[:1] == ["status"]:
        if state["status_exit"]:
            fail("failed to connect to the gateway", state["status_exit"])
        print(json.dumps({"status": state["status"], "version": state["gateway_version"]}))
    elif args[:1] == ["logs"]:
        print(state["logs"])
    elif command == ["workspace", "get"]:
        if rest[0] not in state["workspaces"]:
            fail("code: 'Some requested entity was not found', message: \"workspace not found\"")
        print("Workspace:\n\n  Name: " + rest[0])
    elif command == ["workspace", "create"]:
        state["workspaces"].append(option(rest, "--name"))
        save(state)
    elif command == ["policy", "get"]:
        if state["global_policy"]:
            print("Global policy\n  Version: 1")
            return
        fail("code: 'Some requested entity was not found', message: \"no global policy\n"
             "  │ revision found\"")
    elif command == ["sandbox", "create"]:
        if len(option(rest, "--name")) > 19:
            fail("code: 'Client specified an invalid argument',"
                 " message: \"name exceeds maximum length\"")
        if state["create_exit"] or not Path(option(rest, "--policy")).is_file():
            fail("the sandbox was rejected")
        labels = dict(
            rest[i + 1].split("=", 1) for i, item in enumerate(rest) if item == "--label"
        )
        sandbox = {
            "id": str(uuid.uuid4()),
            "name": option(rest, "--name"),
            "phase": state["create_phase"],
            "admission": state["admission"],
            "labels": labels,
            "workspace": workspace,
            "policy": Path(option(rest, "--policy")).read_text(),
        }
        sandboxes[sandbox["name"]] = sandbox
        save(state)
        sys.stderr.write("Provisioning sandbox (structured output on stdout)...\n")
        print(json.dumps(record(sandbox)))
    elif command == ["sandbox", "get"]:
        sandbox = sandboxes.get(rest[0])
        if sandbox is None or sandbox["workspace"] != workspace:
            fail("code: 'Some requested entity was not found', message: \"sandbox not found\"")
        if "--policy-only" in rest:
            print(state["effective_policy"] or sandbox["policy"])
        else:
            print(json.dumps(record(sandbox)))
    elif command == ["sandbox", "list"]:
        mine = [s for s in sandboxes.values() if s["workspace"] == workspace]
        key, value = option(rest, "--selector").split("=", 1)
        if not state["ignore_selector"]:
            mine = [s for s in mine if s["labels"].get(key) == value]
        start = int(option(rest, "--page-token") or 0)
        page = mine[start:start + state["page_size"]]
        more = start + state["page_size"] < len(mine)
        token = str(start + state["page_size"]) if more else ""
        print(json.dumps({"sandboxes": [record(s) for s in page], "next_page_token": token}))
    elif command == ["sandbox", "exec"]:
        name = option(rest, "--name")
        if name not in sandboxes:
            fail("code: 'Some requested entity was not found', message: \"sandbox not found\"")
        argv = rest[rest.index("--") + 1:]
        script = state["exec"].get(" ".join(argv), {})
        timeout = int(option(rest, "--timeout"))
        if script.get("sleep", 0) > timeout:
            time.sleep(timeout)
            sys.exit(124)
        time.sleep(script.get("sleep", 0))
        sys.stdout.write(script.get("stdout", "") + "x" * script.get("flood", 0))
        sys.stderr.write(script.get("stderr", ""))
        sys.exit(script.get("exit", 0))
    elif command == ["sandbox", "delete"]:
        for name in rest:
            if name in sandboxes and not state["delete_lingers"]:
                del sandboxes[name]
        save(state)
        print("deletion accepted")
    else:
        fail("unexpected command " + " ".join(args), 2)


state = json.loads(STATE.read_text())
with (HERE / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps({"program": Path(sys.argv[0]).name, "argv": sys.argv[1:],
                            "env": dict(os.environ)}) + "\n")
if Path(sys.argv[0]).name == "openshell-prover":
    prover(state, sys.argv[1:])
else:
    openshell(state, sys.argv[1:])
"""

DEFAULT_STATE: dict[str, Any] = {
    "version": "0.1.7",
    "prover_version": "0.1.7",
    "gateway_version": "0.1.7",
    "status": "connected",
    "status_exit": 0,
    "workspaces": ["default", "aegis"],
    "global_policy": False,
    "create_exit": 0,
    "create_phase": "Ready",
    "admission": "accepted",
    "ignore_selector": False,
    "page_size": 100,
    "delete_lingers": False,
    "sandboxes": {},
    "exec": {},
    "effective_policy": None,
    "verdict_sequence": [],
    "proven": [],
    "logs": "",
    "verdict": {
        "result": "within_boundary",
        "exit_code": 0,
        "coverage": {
            "domains": ["filesystem", "network_l4", "network_rest", "process", "landlock"]
        },
        "counterexample": None,
        "reason_code": None,
    },
}


class FakeOpenShell:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.cli = root / "openshell"
        self.prover = root / "openshell-prover"
        for program in (self.cli, self.prover):
            program.write_text(f"#!{sys.executable} -I\n{SCRIPT}")
            program.chmod(0o755)
        self._state = root / "state.json"
        self._calls = root / "calls.jsonl"
        self._state.write_text(json.dumps(DEFAULT_STATE))

    @property
    def state(self) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(self._state.read_text())
        return value

    def update(self, **changes: Any) -> None:
        self._state.write_text(json.dumps({**self.state, **changes}))

    def add_sandbox(self, name: str, *, workspace: str = "aegis", **labels: str) -> None:
        sandboxes = self.state["sandboxes"]
        sandboxes[name] = {
            "id": f"id-{name}",
            "name": name,
            "phase": "Ready",
            "admission": "accepted",
            "labels": labels,
            "workspace": workspace,
            "policy": "version: 1\n",
        }
        self.update(sandboxes=sandboxes)

    def calls(self) -> list[dict[str, Any]]:
        if not self._calls.exists():
            return []
        return [json.loads(line) for line in self._calls.read_text().splitlines()]

    def commands(self) -> list[tuple[str, ...]]:
        # The program and its command words, without flags or values: ("openshell", "sandbox",
        # "get"), or ("openshell", "--version").
        found = []
        for call in self.calls():
            argv = call["argv"]
            while argv[:1] and argv[0] in ("--gateway", "--workspace", "--color"):
                argv = argv[2:]
            words = argv[:1] if argv[:1] == ["--version"] else []
            for arg in argv[: 2 if argv[:1] != ["--version"] else 0]:
                if arg.startswith("-"):
                    break
                words.append(arg)
            found.append((call["program"], *words))
        return found

    def runtime(
        self,
        settings: OpenShellSettings | None = None,
        *,
        environ: dict[str, str] | None = None,
    ) -> OpenShellRuntime:
        settings = settings or OpenShellSettings()
        cli = OpenShellCli(
            settings.gateway,
            settings.workspace,
            executable=self.cli,
            prover=self.prover,
            environ=dict(os.environ) if environ is None else environ,
        )
        return OpenShellRuntime(settings, cli=cli, delete_wait_seconds=0)
