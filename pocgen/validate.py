"""Validation helpers for generated PoC artifacts."""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


SUCCESS_RE = re.compile(
    r"^\s*(?:PASS|JSFLOW_POC_SUCCESS|POC_SUCCESS|poc success)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class ValidationResult:
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


def default_command(output_dir: str | Path) -> list[str] | None:
    root = Path(output_dir).expanduser().resolve()
    for name in ("poc.js", "poc.cjs"):
        if (root / name).is_file():
            return ["node", str(root / name)]
    if (root / "poc.mjs").is_file():
        return ["node", str(root / "poc.mjs")]
    for path in _modified_template_artifacts(root):
        return ["node", str(path)]
    return None


def _modified_template_artifacts(root: Path) -> list[Path]:
    template_dir = Path(__file__).resolve().parent / "templates"
    candidates = []
    for name in ("direct-call.cjs", "proto-poc.cjs", "esm-import.mjs"):
        artifact = root / name
        template = template_dir / name
        if not artifact.is_file() or not template.is_file():
            continue
        if artifact.read_bytes() != template.read_bytes():
            candidates.append(artifact)
    return candidates


def _text_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def validate_output(
    output_dir: str | Path,
    *,
    command: list[str] | None = None,
    timeout: int = 30,
) -> ValidationResult:
    command = default_command(output_dir) if command is None else command
    if not command:
        return ValidationResult(
            status="not_run",
            command=[],
            returncode=None,
            stdout="",
            stderr="",
            notes=(
                "No runnable poc.js, poc.cjs, poc.mjs, or modified template "
                "artifact was found."
            ),
        )
    try:
        proc = subprocess.run(
            command,
            cwd=str(Path(output_dir).expanduser().resolve()),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return ValidationResult(
            status="error",
            command=command,
            returncode=None,
            stdout="",
            stderr=str(exc),
            notes="Validation command could not be started.",
        )
    except subprocess.TimeoutExpired as exc:
        return ValidationResult(
            status="timeout",
            command=command,
            returncode=None,
            stdout=_text_output(exc.stdout),
            stderr=_text_output(exc.stderr),
            notes=f"Validation timed out after {timeout}s.",
        )

    combined = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode == 0 and SUCCESS_RE.search(combined):
        status = "passed"
        notes = "Success marker observed."
    elif proc.returncode == 0:
        status = "ran_no_oracle"
        notes = "PoC ran successfully, but no success marker was observed."
    else:
        status = "failed"
        notes = "PoC command returned a non-zero exit code."
    return ValidationResult(
        status=status,
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        notes=notes,
    )
