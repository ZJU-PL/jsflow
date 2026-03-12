#!/usr/bin/env python3
"""Normalize raw jsflow outputs into the skill's finding schema."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


VULN_ALIASES = {
    "command-injection": "os_command",
    "os_command": "os_command",
    "xss": "xss",
    "code_exec": "code_exec",
    "code-injection": "code_exec",
    "proto_pollution": "proto_pollution",
    "prototype-pollution": "proto_pollution",
    "int_prop_tampering": "int_prop_tampering",
    "internal-property-tampering": "int_prop_tampering",
    "path_traversal": "path_traversal",
    "path-traversal": "path_traversal",
    "nosql": "nosql",
    "nosql-injection": "nosql",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize a raw jsflow finding or taint summary into the PoC skill schema.",
    )
    parser.add_argument("input", nargs="?", help="Path to raw or normalized JSON. Reads stdin if omitted.")
    parser.add_argument("--index", type=int, default=0, help="Finding index when the input is an array.")
    parser.add_argument("--finding-id", help="Override finding_id.")
    parser.add_argument("--package-root", help="Override target.package_root.")
    parser.add_argument("--require-path", help="Override target.require_path.")
    parser.add_argument("--entry-function", help="Override target.entry_function.")
    parser.add_argument(
        "--invocation-mode",
        default="unknown",
        choices=[
            "direct_call",
            "constructor",
            "module_init",
            "callback",
            "cli",
            "http_route",
            "unknown",
        ],
        help="Override invocation.mode.",
    )
    parser.add_argument("--async", dest="is_async", action="store_true", help="Mark the entrypoint as async.")
    parser.add_argument("--module-mode", action="store_true", help="Mark the target as a module analysis target.")
    parser.add_argument(
        "--export-style",
        default="unknown",
        choices=["commonjs", "esm", "unknown"],
        help="Override target.export_style.",
    )
    parser.add_argument("--payload", action="append", default=[], help="Add payload candidates as input=value.")
    parser.add_argument(
        "--oracle-type",
        choices=[
            "stdout",
            "file_exists",
            "response_contains",
            "property_polluted",
            "return_value",
            "side_effect",
            "custom",
        ],
        default="custom",
        help="Set oracle.type.",
    )
    parser.add_argument("--oracle-marker", help="Set oracle.marker.")
    return parser.parse_args()


def load_json(input_path: str | None):
    if input_path:
        return json.loads(Path(input_path).read_text())
    return json.load(sys.stdin)


def coerce_finding(raw_doc, index: int):
    if isinstance(raw_doc, list):
        if not raw_doc:
            raise ValueError("input array is empty")
        try:
            return raw_doc[index]
        except IndexError as exc:
            raise ValueError(f"finding index {index} is out of range") from exc
    if isinstance(raw_doc, dict):
        return raw_doc
    raise ValueError("input must be a JSON object or array")


def normalize_vuln_type(value: str | None) -> str:
    if not value:
        return "os_command"
    return VULN_ALIASES.get(value, value)


def parse_payloads(entries: list[str]) -> list[dict]:
    payloads = []
    for entry in entries:
        if "=" not in entry:
            raise ValueError(f"invalid payload override: {entry!r}")
        input_name, candidate = entry.split("=", 1)
        payloads.append({"input": input_name, "candidate": candidate})
    return payloads


def _read_text(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    try:
        return path.read_text()
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def _infer_export_metadata(entry_text: str) -> dict:
    if re.search(r"module\.exports\s*=\s*function\b", entry_text):
        return {
            "entry_function": None,
            "exported_symbol_kind": "function",
            "candidate_calls": ["target(payload)"],
            "source_symbol": "module.exports",
        }
    if re.search(r"module\.exports\s*=\s*\{", entry_text):
        return {
            "entry_function": None,
            "exported_symbol_kind": "object",
            "candidate_calls": [],
            "source_symbol": "module.exports",
        }

    prop_match = re.search(r"module\.exports\.(\w+)\s*=", entry_text)
    if prop_match:
        entry_function = prop_match.group(1)
        return {
            "entry_function": entry_function,
            "exported_symbol_kind": "object",
            "candidate_calls": [f"target.{entry_function}(payload)"],
            "source_symbol": f"module.exports.{entry_function}",
        }

    exports_match = re.search(r"exports\.(\w+)\s*=", entry_text)
    if exports_match:
        entry_function = exports_match.group(1)
        return {
            "entry_function": entry_function,
            "exported_symbol_kind": "object",
            "candidate_calls": [f"target.{entry_function}(payload)"],
            "source_symbol": f"exports.{entry_function}",
        }

    return {
        "entry_function": None,
        "exported_symbol_kind": "unknown",
        "candidate_calls": [],
        "source_symbol": "input",
    }


def _extract_call_aliases(entry_text: str, module_name: str, members: set[str]) -> dict[str, str]:
    aliases = {}
    prop_pattern = re.compile(
        rf"(?:var|let|const)\s+(\w+)\s*=\s*require\(['\"]{re.escape(module_name)}['\"]\)\.(\w+)"
    )
    for alias, member in prop_pattern.findall(entry_text):
        if member in members:
            aliases[alias] = member

    destructure_pattern = re.compile(
        rf"(?:var|let|const)\s*\{{([^}}]+)\}}\s*=\s*require\(['\"]{re.escape(module_name)}['\"]\)"
    )
    for group in destructure_pattern.findall(entry_text):
        for name in group.split(","):
            member = name.strip().split(":")[-1].strip()
            if member in members:
                aliases[member] = member
    return aliases


def _find_application_sink(entry_path: Path | None, vul_type: str, source_line: int | None) -> dict | None:
    entry_text = _read_text(entry_path)
    if not entry_text:
        return None
    lines = entry_text.splitlines()
    preferred_after = source_line or 1

    if vul_type == "os_command":
        members = {"exec", "execSync", "execFile", "spawn", "spawnSync"}
        aliases = _extract_call_aliases(entry_text, "child_process", members)
        patterns = []
        for alias, member in aliases.items():
            patterns.append((re.compile(rf"\b{re.escape(alias)}\s*\("), f"child_process.{member}"))
        for member in members:
            patterns.append((re.compile(rf"\bchild_process\.{member}\s*\("), f"child_process.{member}"))
            patterns.append((re.compile(rf"\b{member}\s*\("), f"child_process.{member}"))
    elif vul_type == "path_traversal":
        members = {"readFile", "readFileSync", "sendFile"}
        aliases = _extract_call_aliases(entry_text, "fs", members)
        patterns = []
        for alias, member in aliases.items():
            patterns.append((re.compile(rf"\b{re.escape(alias)}\s*\("), f"fs.{member}"))
        for member in members:
            patterns.append((re.compile(rf"\bfs\.{member}\s*\("), f"fs.{member}"))
            patterns.append((re.compile(rf"\b{member}\s*\("), f"fs.{member}"))
    elif vul_type == "code_exec":
        patterns = [
            (re.compile(r"\beval\s*\("), "eval"),
            (re.compile(r"\bFunction\s*\("), "Function"),
        ]
    else:
        patterns = []

    matches = []
    for lineno, line in enumerate(lines, start=1):
        for pattern, symbol in patterns:
            if pattern.search(line):
                score = (lineno < preferred_after, abs(lineno - preferred_after))
                matches.append((score, lineno, symbol, line.rstrip()))
                break

    if not matches:
        return None

    _, lineno, symbol, code = sorted(matches)[0]
    return {
        "symbol": symbol,
        "file": str(entry_path),
        "line": lineno,
        "code": f"{lineno}: {code.strip()}",
    }


def _dedupe_payload_candidates(report: dict, source_symbol: str) -> list[dict]:
    ranked = {}
    status_rank = {"solved": 2, "partial": 1}
    for exploit in report.get("exploit_results", []):
        candidate = exploit.get("payload")
        status = exploit.get("status")
        if candidate is None or status not in {"solved", "partial"}:
            continue
        current = ranked.get(candidate)
        record = {
            "input": source_symbol or exploit.get("source_name") or "input",
            "candidate": candidate,
            "reason": f"Recovered from jsflow exploit result status={status}",
            "_rank": status_rank[status],
        }
        if current is None or record["_rank"] > current["_rank"]:
            ranked[candidate] = record

    payloads = []
    for record in ranked.values():
        payloads.append(
            {
                "input": record["input"],
                "candidate": record["candidate"],
                "reason": record["reason"],
            }
        )
    return payloads[:8]


def _recover_oracle(vul_type: str, payload_candidates: list[dict]) -> dict:
    if vul_type == "os_command":
        for payload in payload_candidates:
            candidate = str(payload.get("candidate", ""))
            touch_match = re.search(r"touch\s+([^\s;&|#]+)", candidate)
            if touch_match:
                return {
                    "type": "file_exists",
                    "file_path": touch_match.group(1),
                    "notes": "Recovered marker file oracle from exploit payload.",
                }
            echo_match = re.search(r"echo\s+([A-Za-z0-9_./-]+)", candidate)
            if echo_match:
                return {
                    "type": "stdout",
                    "marker": echo_match.group(1),
                    "notes": "Recovered stdout oracle from exploit payload.",
                }
    return {
        "type": "custom",
        "marker": "",
        "notes": "No concrete oracle could be recovered directly from the report.",
    }


def _candidate_calls_from_report(finding: dict) -> list[str]:
    source = finding.get("source") or {}
    sink = finding.get("sink") or {}
    calls = []
    if source.get("function"):
        calls.append(source["function"])
    if sink.get("function") and sink.get("function") not in calls:
        calls.append(sink["function"])
    return calls


def _payload_candidates_from_report(report: dict) -> list[dict]:
    payloads = []
    for exploit in report.get("exploit_results", []):
        candidate = {
            "input": exploit.get("source_name") or "input",
            "candidate": exploit.get("payload"),
            "reason": f"Recovered from jsflow exploit result status={exploit.get('status')}",
        }
        if candidate["candidate"] is not None:
            payloads.append(candidate)
    return payloads


def _normalize_from_report(report: dict, args: argparse.Namespace) -> dict:
    findings = report.get("findings") or []
    if not findings:
        raise ValueError("report contains no findings")
    try:
        finding = findings[args.index]
    except IndexError as exc:
        raise ValueError(f"finding index {args.index} is out of range") from exc

    run = report.get("run", {})
    source = finding.get("source") or {}
    sink = finding.get("sink") or {}
    poc_guidance = finding.get("poc_guidance") or {}
    public_entrypoint = poc_guidance.get("public_entrypoint") or {}
    poc_invocation = poc_guidance.get("invocation") or {}
    poc_sink = poc_guidance.get("application_sink") or {}
    poc_oracle = poc_guidance.get("suggested_oracle") or {}
    path = finding.get("path") or {}
    entry_file = run.get("entry_file") or source.get("file") or sink.get("file") or ""
    entry_path = Path(entry_file) if entry_file else None
    entry_text = _read_text(entry_path)
    export_metadata = _infer_export_metadata(entry_text) if not public_entrypoint else None
    source_symbol = public_entrypoint.get("symbol") or (
        export_metadata["source_symbol"] if export_metadata else source.get("function") or "input"
    )
    payload_candidates = poc_guidance.get("payload_candidates") or _dedupe_payload_candidates(report, source_symbol)
    recovered_sink = poc_sink or _find_application_sink(
        entry_path, normalize_vuln_type(run.get("vulnerability_type")), source.get("line")
    )
    oracle = poc_oracle or _recover_oracle(normalize_vuln_type(run.get("vulnerability_type")), payload_candidates)
    candidate_calls = poc_invocation.get("candidate_calls") or (
        export_metadata["candidate_calls"] if export_metadata else _candidate_calls_from_report(finding)
    )
    entry_function = public_entrypoint.get("entry_function")
    if entry_function is None and export_metadata:
        entry_function = export_metadata["entry_function"]
    exported_symbol_kind = public_entrypoint.get("exported_symbol_kind")
    if exported_symbol_kind is None and export_metadata:
        exported_symbol_kind = export_metadata["exported_symbol_kind"]
    require_path = public_entrypoint.get("require_path") or args.require_path or (
        f"./{entry_path.name}" if entry_path else ""
    )
    package_root = public_entrypoint.get("package_root") or args.package_root or (
        str(entry_path.parent) if entry_path else ""
    )
    invocation_mode = poc_invocation.get("mode") or args.invocation_mode

    normalized = {
        "finding_id": args.finding_id or finding.get("id") or f"report-{args.index}",
        "normalized_from": "report",
        "vulnerability_type": normalize_vuln_type(run.get("vulnerability_type")),
        "target": {
            "package_root": package_root,
            "entry_file": public_entrypoint.get("entry_file") or (entry_path.name if entry_path else ""),
            "require_path": require_path,
            "entry_function": args.entry_function or entry_function,
            "exported_symbol_kind": exported_symbol_kind or "unknown",
            "module_mode": args.module_mode or bool(run.get("module_mode")),
            "export_style": args.export_style,
            "is_async": args.is_async,
        },
        "invocation": {
            "mode": invocation_mode if invocation_mode != "unknown" else "direct_call",
            "candidate_calls": candidate_calls,
        },
        "source": {
            "kind": "tainted_flow",
            "symbol": source_symbol,
            "file": source.get("file"),
            "line": source.get("line"),
        },
        "sink": recovered_sink
        or {
            "symbol": sink.get("function") or sink.get("type") or sink.get("id") or "sink",
            "file": sink.get("file"),
            "line": sink.get("line"),
            "code": sink.get("code"),
        },
        "trace": {
            "path_text": path.get("text", ""),
            "nodes": [
                {
                    "id": node.get("id"),
                    "file": node.get("file"),
                    "line": node.get("line"),
                    "code": node.get("code"),
                }
                for node in path.get("nodes", [])
            ],
        },
        "constraints": {
            "available": bool(payload_candidates),
            "payload_candidates": payload_candidates,
        },
        "oracle": oracle if args.oracle_type == "custom" and not args.oracle_marker else {
            "type": args.oracle_type,
            "marker": args.oracle_marker or "",
            "notes": finding.get("message"),
        },
        "environment": {
            "cwd": str(entry_path.parent) if entry_path else "",
            "notes": f"Recovered from jsflow report version={report.get('version')}",
        },
        "validation": {
            "status": "not_run",
            "run_command": "",
            "observed_output": "",
        },
        "raw_jsflow": {
            "report_finding_id": finding.get("id"),
            "report_status": finding.get("status"),
            "report_message": finding.get("message"),
            "report_log_dir": run.get("log_dir"),
        },
        "assumptions": [
            "Recovered from canonical jsflow report.json output.",
            "Preferred jsflow report poc guidance when available.",
        ],
    }
    return normalized


def normalize(raw_doc, args: argparse.Namespace) -> dict:
    finding = coerce_finding(raw_doc, args.index)

    if isinstance(finding, dict) and "findings" in finding and "summary" in finding:
        normalized = _normalize_from_report(finding, args)
    elif "vulnerability_type" in finding and "target" in finding:
        normalized = dict(finding)
        normalized["vulnerability_type"] = normalize_vuln_type(
            normalized.get("vulnerability_type")
        )
    else:
        filename = finding.get("filename", "")
        entry_file = Path(filename).name if filename else ""
        normalized = {
            "finding_id": args.finding_id or f"raw-{args.index}",
            "normalized_from": "raw_jsflow",
            "vulnerability_type": normalize_vuln_type(finding.get("vuln_type")),
            "target": {
                "package_root": args.package_root or (str(Path(filename).parent) if filename else ""),
                "entry_file": entry_file,
                "require_path": args.require_path or (f"./{entry_file}" if entry_file else ""),
                "entry_function": args.entry_function,
                "exported_symbol_kind": "unknown",
                "module_mode": args.module_mode,
                "export_style": args.export_style,
                "is_async": args.is_async,
            },
            "invocation": {
                "mode": args.invocation_mode,
            },
            "sink": {
                "symbol": finding.get("sink", ""),
                "file": filename,
                "line": finding.get("sink_lineno"),
                "code": finding.get("sink", ""),
            },
            "trace": {
                "path_text": finding.get("path_text", ""),
            },
            "constraints": {
                "available": bool(args.payload),
                "payload_candidates": [],
            },
            "oracle": {
                "type": args.oracle_type,
                "marker": args.oracle_marker or "",
            },
            "environment": {},
            "validation": {
                "status": "not_run",
                "run_command": "",
                "observed_output": "",
            },
            "raw_jsflow": finding,
            "assumptions": [],
        }

    payloads = parse_payloads(args.payload)
    if payloads:
        normalized.setdefault("constraints", {})
        normalized["constraints"]["available"] = True
        normalized["constraints"]["payload_candidates"] = payloads

    normalized.setdefault("finding_id", args.finding_id or "normalized-finding")
    normalized.setdefault("normalized_from", "manual")
    normalized.setdefault("validation", {"status": "not_run"})

    target = normalized.setdefault("target", {})
    if args.package_root:
        target["package_root"] = args.package_root
    if args.require_path:
        target["require_path"] = args.require_path
    if args.entry_function:
        target["entry_function"] = args.entry_function
    target.setdefault("export_style", args.export_style)
    target.setdefault("module_mode", args.module_mode)
    target.setdefault("is_async", args.is_async)

    invocation = normalized.setdefault("invocation", {})
    invocation.setdefault("mode", args.invocation_mode)

    oracle = normalized.setdefault("oracle", {})
    oracle.setdefault("type", args.oracle_type)
    if args.oracle_marker and not oracle.get("marker"):
        oracle["marker"] = args.oracle_marker

    return normalized


def main() -> int:
    args = parse_args()
    try:
        raw_doc = load_json(args.input)
        normalized = normalize(raw_doc, args)
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 1

    json.dump(normalized, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
