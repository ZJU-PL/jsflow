"""Helpers for extracting agent-facing PoC packets from jsflow reports."""

from __future__ import annotations

import json
from os import PathLike
from pathlib import Path
from typing import Any


class PacketError(ValueError):
    """Raised when a report does not contain a usable PoC packet."""


def load_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path).expanduser()
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PacketError(f"report not found: {report_path}") from exc
    except json.JSONDecodeError as exc:
        raise PacketError(f"invalid report JSON: {report_path}") from exc
    if not isinstance(data, dict):
        raise PacketError("report root must be a JSON object")
    return data


def select_finding(report: dict[str, Any], selector: str | int = 0) -> dict[str, Any]:
    findings = report.get("findings")
    if not isinstance(findings, list) or not findings:
        raise PacketError("report does not contain findings")

    if isinstance(selector, int) or str(selector).isdigit():
        index = int(selector)
        try:
            finding = findings[index]
        except IndexError as exc:
            raise PacketError(f"finding index out of range: {index}") from exc
        if not isinstance(finding, dict):
            raise PacketError(f"finding at index {index} is not an object")
        return finding

    for finding in findings:
        if isinstance(finding, dict) and finding.get("id") == selector:
            return finding
    raise PacketError(f"finding id not found: {selector}")


def extract_poc(finding: dict[str, Any]) -> dict[str, Any]:
    poc = finding.get("poc")
    if not isinstance(poc, dict):
        raise PacketError("finding does not contain finding.poc")
    return poc


def extract_agent_packet(finding: dict[str, Any]) -> dict[str, Any]:
    poc = extract_poc(finding)
    packet = poc.get("agent_packet")
    if isinstance(packet, dict):
        return packet
    environment = _dict_field(poc, "environment")
    target = _dict_field(poc, "target")
    invocation = _dict_field(poc, "invocation")
    source = _dict_field(poc, "source")

    # Compatibility fallback for older report versions.
    return {
        "purpose": "Generate the smallest safe PoC harness for this jsflow finding.",
        "finding_id": finding.get("id") or poc.get("finding_id"),
        "vulnerability_type": poc.get("vulnerability_type"),
        "target": {
            "cwd": environment.get("cwd"),
            "require_path": target.get("require_path"),
            "module_system": target.get("export_style"),
            "preferred_call": _first_string(invocation.get("candidate_calls")),
        },
        "payload": {
            "source_binding": source.get("symbol"),
            "candidate": _first_payload(poc),
            "expectation": "",
        },
        "sink": poc.get("sink"),
        "validation": poc.get("oracle"),
        "runtime": {},
        "thin_slice_summary": [],
        "recommended_harness": {},
        "todo": [],
        "uncertainty": poc.get("assumptions", []),
    }


def _first_payload(poc: dict[str, Any]) -> Any:
    candidates = _dict_field(poc, "constraints").get("payload_candidates")
    if isinstance(candidates, list) and candidates:
        first = candidates[0]
        if isinstance(first, dict):
            return first.get("candidate")
    return None


def _dict_field(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _first_string(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                return item
    if isinstance(value, str):
        return value
    return ""


def evidence_pointer(report_path: str | Path, selector: str | int) -> dict[str, str]:
    return {
        "evidence_uri": str(Path(report_path).expanduser().resolve()),
        "evidence_path": (
            f"$.findings[{selector}].poc"
            if isinstance(selector, int) or str(selector).isdigit()
            else f"$.findings[?(@.id == {json.dumps(str(selector))})].poc"
        ),
    }


def target_cwd(report: dict[str, Any], poc: dict[str, Any], report_path: str | Path) -> Path:
    packet = _dict_field(poc, "agent_packet")
    packet_target = _dict_field(packet, "target")
    target = _dict_field(poc, "target")
    run = _dict_field(report, "run")
    packet_cwd = packet_target.get("cwd")
    for candidate in (
        packet_cwd,
        _dict_field(poc, "runtime_environment").get("cwd"),
        _dict_field(poc, "environment").get("cwd"),
    ):
        if _is_path_value(candidate):
            path = Path(candidate).expanduser()
            if path.is_dir():
                return path.resolve()
            if path.is_file():
                return path.parent.resolve()

    entry_file = (
        target.get("entry_file")
        or run.get("entry_file")
        or run.get("input_file")
    )
    if _is_path_value(entry_file):
        entry_path = Path(entry_file).expanduser()
        if entry_path.is_file():
            return entry_path.parent.resolve()
        if entry_path.is_dir():
            return entry_path.resolve()

    return Path(report_path).expanduser().resolve().parent


def _is_path_value(value: Any) -> bool:
    return isinstance(value, str | PathLike) and bool(value)
