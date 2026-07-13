#!/usr/bin/env python3
"""Automated probejs PoC generation runner."""

from __future__ import annotations

import argparse
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pocgen.agent_runner import AgentRunError, run_agent, supported_agents
from pocgen.evidence import dumps_json, evidence_for_stage, render_json
from pocgen.packet import (
    PacketError,
    evidence_pointer,
    extract_agent_packet,
    extract_poc,
    load_report,
    select_finding,
    target_cwd,
)
from pocgen.prompts import render
from pocgen.validate import validate_output


def build_prompt(
    *,
    agent_packet: dict[str, Any],
    evidence: dict[str, Any],
    output_dir: Path,
    target_cwd: Path,
    report_path: Path,
    finding_selector: str,
) -> str:
    pointer = evidence_pointer(report_path, finding_selector)
    return render(
        "generate.md",
        agent_packet=render_json(agent_packet, max_chars=20_000),
        evidence=render_json(evidence, max_chars=30_000),
        evidence_uri=pointer["evidence_uri"],
        evidence_path=pointer["evidence_path"],
        output_dir=str(output_dir.resolve()),
        target_cwd=str(target_cwd.resolve()),
    )


def repair_prompt(
    *,
    agent_packet: dict[str, Any],
    evidence: dict[str, Any],
    validation: dict[str, Any],
    output_dir: Path,
    target_cwd: Path,
    report_path: Path,
    finding_selector: str,
) -> str:
    pointer = evidence_pointer(report_path, finding_selector)
    return render(
        "repair.md",
        agent_packet=render_json(agent_packet, max_chars=20_000),
        evidence=render_json(evidence, max_chars=30_000),
        validation=render_json(validation, max_chars=12_000),
        evidence_uri=pointer["evidence_uri"],
        evidence_path=pointer["evidence_path"],
        output_dir=str(output_dir.resolve()),
        target_cwd=str(target_cwd.resolve()),
    )


def copy_templates(output_dir: Path) -> None:
    template_dir = Path(__file__).resolve().parent / "templates"
    output_dir.mkdir(parents=True, exist_ok=True)
    for template in template_dir.glob("*"):
        if template.is_file():
            dst = output_dir / template.name
            if not dst.exists():
                shutil.copyfile(template, dst)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_json(data) + "\n", encoding="utf-8")


def parse_validation_command(value: str | None) -> list[str] | None:
    if not value:
        return None
    try:
        tokens = shlex.split(value)
    except ValueError as exc:
        raise PacketError(f"invalid --validation-command: {exc}") from exc
    return tokens or None


def validate_generation_options(args: argparse.Namespace) -> list[str] | None:
    if args.timeout <= 0:
        raise PacketError("--timeout must be greater than 0")
    if args.validation_timeout <= 0:
        raise PacketError("--validation-timeout must be greater than 0")
    if args.max_repairs < 0:
        raise PacketError("--max-repairs must be greater than or equal to 0")
    if args.max_evidence_chars < 0:
        raise PacketError("--max-evidence-chars must be greater than or equal to 0")
    return parse_validation_command(args.validation_command)


def resolve_codebase_override(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise PacketError(f"--codebase must be an existing directory: {path}")
    return path


def resolve_output_dir(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if path.exists() and not path.is_dir():
        raise PacketError(f"--output must be a directory, not a file: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PacketError(f"could not create --output directory {path}: {exc}") from exc
    return path


def run_generation(args: argparse.Namespace) -> dict[str, Any]:
    validation_command = validate_generation_options(args)
    report_path = Path(args.report).expanduser().resolve()
    report = load_report(report_path)
    finding = select_finding(report, args.finding)
    poc = extract_poc(finding)
    agent_packet = extract_agent_packet(finding)
    cwd = resolve_codebase_override(args.codebase) or target_cwd(report, poc, report_path)
    output_dir = resolve_output_dir(args.output)
    if args.copy_templates:
        copy_templates(output_dir)

    write_json(output_dir / "agent_packet.json", agent_packet)
    write_json(output_dir / "finding_poc.json", poc)

    attempts = []
    validation = {"status": "not_run", "notes": "Generation has not run yet."}
    max_stage = args.max_repairs

    for stage in range(max_stage + 1):
        evidence = evidence_for_stage(finding, stage=stage, max_chars=args.max_evidence_chars)
        prompt = (
            build_prompt(
                agent_packet=agent_packet,
                evidence=evidence,
                output_dir=output_dir,
                target_cwd=cwd,
                report_path=report_path,
                finding_selector=str(args.finding),
            )
            if stage == 0
            else repair_prompt(
                agent_packet=agent_packet,
                evidence=evidence,
                validation=validation,
                output_dir=output_dir,
                target_cwd=cwd,
                report_path=report_path,
                finding_selector=str(args.finding),
            )
        )
        prompt_path = output_dir / f"prompt-stage-{stage}.md"
        prompt_path.write_text(prompt, encoding="utf-8")

        attempt = {
            "stage": stage,
            "prompt": str(prompt_path),
            "evidence_stage": evidence["stage"],
            "agent": args.agent,
            "dry_run": bool(args.dry_run),
        }
        if args.dry_run:
            attempt["status"] = "skipped"
            attempt["notes"] = "Dry run: prompt and packet were written, agent was not called."
            attempts.append(attempt)
            break

        try:
            result = run_agent(
                prompt,
                cwd=cwd,
                agent=args.agent,
                model=args.model,
                timeout=args.timeout,
                extra_args=args.agent_arg,
            )
            attempt["status"] = "agent_completed"
            attempt["agent_text"] = result.text
            attempt["command"] = result.command
            write_json(output_dir / f"agent-result-stage-{stage}.json", result.raw)
        except AgentRunError as exc:
            attempt["status"] = "agent_error"
            attempt["error"] = str(exc)
            attempts.append(attempt)
            break

        validation_result = validate_output(
            output_dir,
            command=validation_command,
            timeout=args.validation_timeout,
        )
        validation = validation_result.to_dict()
        attempt["validation"] = validation
        attempts.append(attempt)
        if validation["status"] == "passed":
            break

    result_report = {
        "status": _overall_status(attempts, validation),
        "report": str(report_path),
        "finding": args.finding,
        "agent": args.agent,
        "model": args.model,
        "agent_args": args.agent_arg,
        "max_repairs": args.max_repairs,
        "target_cwd": str(cwd),
        "output_dir": str(output_dir),
        "agent_packet_path": str(output_dir / "agent_packet.json"),
        "finding_poc_path": str(output_dir / "finding_poc.json"),
        "validation_command": validation_command,
        "attempts": attempts,
        "validation": validation,
    }
    write_json(output_dir / "pocgen-result.json", result_report)
    return result_report


def _overall_status(attempts: list[dict[str, Any]], validation: dict[str, Any]) -> str:
    if attempts and attempts[-1].get("dry_run"):
        return "dry_run"
    if validation.get("status") == "passed":
        return "validated"
    if any(attempt.get("status") == "agent_completed" for attempt in attempts):
        return "generated_unvalidated"
    return "failed"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate and validate PoCs from probejs reports")
    ap.add_argument("--report", required=True, help="path to probejs report.json")
    ap.add_argument("--finding", default="0", help="finding index or finding id (default: 0)")
    ap.add_argument("--output", required=True, help="directory for generated PoC artifacts")
    ap.add_argument("--codebase", help="override target package root for the coding agent")
    ap.add_argument("--agent", choices=supported_agents(), default="codex")
    ap.add_argument("--model", default="default")
    ap.add_argument(
        "--agent-arg",
        action="append",
        default=[],
        help="extra backend CLI argv token; use --agent-arg=--flag for dashed values",
    )
    ap.add_argument("--timeout", type=int, default=1200, help="agent timeout in seconds")
    ap.add_argument("--validation-timeout", type=int, default=30)
    ap.add_argument(
        "--validation-command",
        help="shell-like command to validate the PoC, executed from the output directory",
    )
    ap.add_argument("--max-repairs", type=int, default=2)
    ap.add_argument("--max-evidence-chars", type=int, default=30_000)
    ap.add_argument("--dry-run", action="store_true", help="write packet/prompts without calling an agent")
    ap.add_argument("--no-copy-templates", dest="copy_templates", action="store_false")
    ap.set_defaults(copy_templates=True)
    args = ap.parse_args(argv)

    try:
        result = run_generation(args)
    except PacketError as exc:
        print(f"pocgen: {exc}", file=sys.stderr)
        return 2

    print(dumps_json(result))
    return 0 if result["status"] in {"dry_run", "validated"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
