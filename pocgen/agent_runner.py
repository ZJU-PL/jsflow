"""Headless CLI coding-agent wrapper for pocgen."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class AgentRunError(RuntimeError):
    """Raised when a CLI agent cannot be executed successfully."""


@dataclass
class AgentResult:
    text: str
    raw: dict[str, Any]
    command: list[str]


BACKENDS: dict[str, dict[str, Any]] = {
    "claude": {
        "command": "claude",
        "prompt_args": ["-p", "{prompt}"],
        "json_output": True,
        "extra_args_before_prompt": False,
    },
    "opencode": {
        "command": "opencode",
        "prompt_args": ["run", "--pure", "--auto", "{prompt}"],
        "json_output": False,
        "extra_args_before_prompt": True,
    },
    "codex": {
        "command": "codex",
        "prompt_args": [
            "exec",
            "--skip-git-repo-check",
            "-s",
            "danger-full-access",
            "{prompt}",
        ],
        "json_output": False,
        "extra_args_before_prompt": True,
    },
}


def supported_agents() -> list[str]:
    return sorted(BACKENDS)


def build_command(
    *,
    agent: str,
    model: str,
    prompt: str,
    extra_args: list[str] | None = None,
) -> list[str]:
    if agent not in BACKENDS:
        raise AgentRunError(f"unsupported agent: {agent}")
    backend = BACKENDS[agent]
    cmd = [backend["command"]]
    for arg in backend["prompt_args"]:
        if arg == "{prompt}" and backend.get("extra_args_before_prompt") and extra_args:
            cmd.extend(extra_args)
        cmd.append(arg.replace("{prompt}", prompt))
    if agent == "claude":
        cmd += [
            "--model",
            model,
            "--dangerously-skip-permissions",
            "--allowedTools",
            "Read,Grep,Glob,Bash,Write,Edit,MultiEdit",
            "--output-format",
            "json",
        ]
    if extra_args and not backend.get("extra_args_before_prompt"):
        cmd.extend(extra_args)
    return cmd


def redact_command(cmd: list[str], prompt: str) -> list[str]:
    return ["<prompt omitted; see prompt-stage-N.md>" if arg == prompt else arg for arg in cmd]


def _text_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _summarize_streams(stdout: str, stderr: str, *, limit: int = 1200) -> str:
    combined = []
    if stdout:
        combined.append(f"stdout:\n{stdout}")
    if stderr:
        combined.append(f"stderr:\n{stderr}")
    text = "\n\n".join(combined)
    return text[:limit] if text else "<no output>"


def run_agent(
    prompt: str,
    *,
    cwd: str | Path,
    agent: str,
    model: str,
    timeout: int,
    extra_args: list[str] | None = None,
) -> AgentResult:
    cwd = Path(cwd).expanduser().resolve()
    if not cwd.is_dir():
        raise AgentRunError(f"agent cwd is not a directory: {cwd}")
    cmd = build_command(
        agent=agent,
        model=model,
        prompt=prompt,
        extra_args=extra_args,
    )
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise AgentRunError(f"`{BACKENDS[agent]['command']}` not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        output = _summarize_streams(_text_output(exc.stdout), _text_output(exc.stderr))
        raise AgentRunError(f"{agent} timed out after {timeout}s: {output}") from exc

    if proc.returncode != 0:
        output = _summarize_streams(proc.stdout, proc.stderr)
        raise AgentRunError(f"{agent} exited {proc.returncode}: {output}")

    if BACKENDS[agent]["json_output"]:
        try:
            raw = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AgentRunError(f"could not parse {agent} JSON output") from exc
        if not isinstance(raw, dict):
            raise AgentRunError(f"{agent} JSON output root must be an object")
        text = str(raw.get("result", ""))
    else:
        raw = {"stdout": proc.stdout, "stderr": proc.stderr}
        text = proc.stdout
    return AgentResult(text=text, raw=raw, command=redact_command(cmd, prompt))
