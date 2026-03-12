"""Structured JSON reporting helpers for jsflow analysis runs."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .vuln.vul_checking import get_path_text
REPORT_SCHEMA = "./report.schema.json"
REPORT_VERSION = "1.2.0"
BUILTIN_PACKAGES_SEGMENT = "/builtin_packages/"


def _safe_method(obj, name, *args, default=None):
    method = getattr(obj, name, None)
    if method is None:
        return default
    try:
        return method(*args)
    except Exception:
        return default


def _to_int(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _serialize_rule_arguments(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_serialize_rule_arguments(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize_rule_arguments(item) for key, item in value.items()}
    return str(value)


def _is_builtin_file(file_path):
    if not file_path:
        return False
    return BUILTIN_PACKAGES_SEGMENT in file_path.replace("\\", "/")


def _read_file_lines(file_path):
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.readlines()
    except (OSError, UnicodeDecodeError):
        return None


def _build_snippet(file_path, line, end_line, fallback=None, *, context_lines=2):
    if line is None:
        return {"text": fallback} if fallback else None
    file_lines = _read_file_lines(file_path)
    if not file_lines:
        return {"text": fallback} if fallback else None

    start_index = max(0, line - 1 - context_lines)
    end_index = min(len(file_lines), (end_line or line) + context_lines)
    return {
        "start_line": start_index + 1,
        "end_line": end_index,
        "text": "".join(file_lines[start_index:end_index]).rstrip(),
    }


def _node_record(G, node_id):
    if node_id is None:
        return None
    attr = _safe_method(G, "get_node_attr", node_id, default={}) or {}
    file_path = _safe_method(G, "get_node_file_path", node_id)
    code = _safe_method(G, "get_node_line_code", node_id)
    if code is not None:
        code = str(code).strip()
    line = _to_int(attr.get("lineno:int") or attr.get("line"))
    end_line = _to_int(attr.get("endlineno:int") or attr.get("end_line"))
    function_id = attr.get("funcid:int")
    function_name = (
        _safe_method(G, "get_name_from_child", function_id)
        if function_id is not None
        else None
    )
    return {
        "id": str(node_id),
        "file": file_path,
        "line": line,
        "end_line": end_line,
        "label": attr.get("labels:label"),
        "type": attr.get("type"),
        "function": function_name,
        "builtin": _is_builtin_file(file_path),
        "code": code,
        "snippet": _build_snippet(file_path, line, end_line, fallback=code),
    }


def _serialize_exploit_reports(exploit_reports):
    serialized = []
    for exploit in exploit_reports or []:
        serialized.append(
            {
                "sink_function": exploit.get("sink_function"),
                "source_name": exploit.get("source_name"),
                "payload": exploit.get("payload"),
                "status": exploit.get("status"),
                "bindings": [
                    {
                        "symbol": binding.get("symbol"),
                        "name": binding.get("name"),
                        "value": binding.get("value"),
                        "role": binding.get("role"),
                    }
                    for binding in exploit.get("bindings", [])
                ],
            }
        )
    return serialized


def _select_endpoint(nodes, *, reverse=False):
    if not nodes:
        return None
    ordered = list(reversed(nodes)) if reverse else list(nodes)
    for node in ordered:
        if node and not node.get("builtin"):
            return node
    return ordered[0]


def _build_message(status):
    if status == "matched":
        return "jsflow matched vulnerability rules for this path."
    if status == "exploit_only":
        return "jsflow solved exploit-like payloads for this path, but rule matching failed."
    return "jsflow found a candidate path that did not satisfy all rules."


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


def _find_application_sink(entry_path: Path | None, vul_type: str, source_line: int | None):
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


def _dedupe_payload_candidates(exploit_reports, source_symbol: str) -> list[dict]:
    ranked = {}
    status_rank = {"solved": 2, "partial": 1}
    for exploit in exploit_reports or []:
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


def _infer_export_style(entry_text: str) -> str:
    if re.search(r"\bmodule\.exports\b|\bexports\.", entry_text):
        return "commonjs"
    if re.search(r"^\s*export\b", entry_text, re.MULTILINE):
        return "esm"
    return "unknown"


def _candidate_calls_from_nodes(source_node, sink_node) -> list[str]:
    calls = []
    for candidate in (
        source_node.get("function") if source_node else None,
        sink_node.get("function") if sink_node else None,
    ):
        if candidate and candidate not in calls:
            calls.append(candidate)
    return calls


def _build_poc_finding(
    G,
    finding_id: str,
    source_node,
    sink_node,
    path_nodes,
    path_text: str,
    exploit_reports,
    *,
    status_message: str,
):
    entry_file = G.entry_file_path or (source_node or {}).get("file") or (sink_node or {}).get("file")
    entry_path = Path(entry_file) if entry_file else None
    entry_text = _read_text(entry_path)
    export_metadata = _infer_export_metadata(entry_text)
    payload_candidates = _dedupe_payload_candidates(
        exploit_reports, export_metadata["source_symbol"]
    )
    application_sink = _find_application_sink(
        entry_path,
        G.vul_type,
        (source_node or {}).get("line"),
    )
    sink_record = application_sink or {
        "symbol": (sink_node or {}).get("function")
        or (sink_node or {}).get("type")
        or (sink_node or {}).get("id")
        or "sink",
        "file": (sink_node or {}).get("file"),
        "line": (sink_node or {}).get("line"),
        "code": (sink_node or {}).get("code"),
    }
    require_path = f"./{entry_path.name}" if entry_path else ""
    package_root = str(entry_path.parent) if entry_path else ""
    package_name = os.path.basename(package_root) if package_root else ""
    candidate_calls = export_metadata["candidate_calls"] or _candidate_calls_from_nodes(
        source_node, sink_node
    )
    oracle = _recover_oracle(G.vul_type, payload_candidates)

    return {
        "finding_id": finding_id,
        "normalized_from": "report",
        "vulnerability_type": G.vul_type,
        "target": {
            "package_name": package_name,
            "package_root": package_root,
            "entry_file": entry_path.name if entry_path else "",
            "require_path": require_path,
            "entry_function": export_metadata["entry_function"],
            "exported_symbol_kind": export_metadata["exported_symbol_kind"],
            "module_mode": bool(getattr(G, "run_all", False)),
            "export_style": _infer_export_style(entry_text),
            "is_async": False,
        },
        "invocation": {
            "mode": "direct_call",
            "candidate_calls": candidate_calls,
        },
        "source": {
            "kind": "tainted_flow",
            "symbol": export_metadata["source_symbol"],
            "file": (source_node or {}).get("file"),
            "line": (source_node or {}).get("line"),
        },
        "sink": sink_record,
        "trace": {
            "path_text": path_text,
            "nodes": [
                {
                    "id": node.get("id"),
                    "file": node.get("file"),
                    "line": node.get("line"),
                    "code": node.get("code"),
                }
                for node in path_nodes
                if node
            ],
        },
        "constraints": {
            "available": bool(payload_candidates),
            "payload_candidates": payload_candidates,
        },
        "oracle": oracle,
        "environment": {
            "cwd": package_root,
            "notes": "Recovered from canonical jsflow report output.",
        },
        "validation": {
            "status": "not_run",
            "run_command": "",
            "observed_output": "",
        },
        "raw_jsflow": {
            "report_finding_id": finding_id,
            "report_message": status_message,
            "report_log_dir": getattr(G, "log_dir", None),
        },
        "assumptions": [
            "Recovered from canonical jsflow report output.",
            "Prefer jsflow-recovered PoC fields over downstream re-inference.",
        ],
    }


def _build_poc_guidance(G, source_node, sink_node, exploit_reports):
    poc = _build_poc_finding(
        G,
        finding_id="report-derived",
        source_node=source_node,
        sink_node=sink_node,
        path_nodes=[],
        path_text="",
        exploit_reports=exploit_reports,
        status_message="report-derived poc guidance",
    )
    return {
        "public_entrypoint": {
            "symbol": poc["source"]["symbol"],
            "entry_file": poc["target"]["entry_file"] or None,
            "package_root": poc["target"]["package_root"] or None,
            "require_path": poc["target"]["require_path"],
            "entry_function": poc["target"]["entry_function"],
            "exported_symbol_kind": poc["target"]["exported_symbol_kind"],
        },
        "invocation": {
            "mode": poc["invocation"]["mode"],
            "candidate_calls": poc["invocation"]["candidate_calls"],
        },
        "application_sink": poc["sink"],
        "payload_candidates": poc["constraints"]["payload_candidates"],
        "suggested_oracle": poc["oracle"],
        "validation": {"status": poc["validation"]["status"]},
    }


def build_analysis_report(
    G,
    args,
    *,
    started_at,
    candidate_paths=None,
    rule_diagnostics=None,
    exploit_reports=None,
):
    candidate_paths = candidate_paths or []
    rule_diagnostics = rule_diagnostics or []
    exploit_reports = exploit_reports or []

    findings = []
    for index, path_diagnostic in enumerate(rule_diagnostics):
        path = list(path_diagnostic.get("path", []))
        if not path:
            continue
        matched = bool(path_diagnostic.get("matched"))
        status = "matched" if matched else "candidate"
        if not matched and any(
            exploit.get("status") in {"solved", "partial"} for exploit in exploit_reports
        ):
            status = "exploit_only"

        path_nodes = [_node_record(G, node) for node in path]
        source_node = _select_endpoint(path_nodes)
        sink_node = _select_endpoint(path_nodes, reverse=True)
        status_message = _build_message(status)
        finding_id = f"jsflow/{G.vul_type}/{index + 1}"
        path_text = get_path_text(G, list(path), path[-1])
        poc_finding = _build_poc_finding(
            G,
            finding_id,
            source_node,
            sink_node,
            path_nodes,
            path_text,
            exploit_reports,
            status_message=status_message,
        )
        findings.append(
            {
                "id": finding_id,
                "rule_id": f"jsflow/{G.vul_type}",
                "status": status,
                "message": status_message,
                "source": source_node,
                "sink": sink_node,
                "poc": poc_finding,
                "poc_guidance": _build_poc_guidance(G, source_node, sink_node, exploit_reports),
                "path": {
                    "node_ids": [str(node) for node in path],
                    "nodes": path_nodes,
                    "text": path_text,
                },
                "rule_evaluation": {
                    "matched": matched,
                    "matched_rule_list": path_diagnostic.get("matched_rule_list"),
                    "rule_lists": [
                        {
                            "rule_list_index": rule_list["rule_list_index"],
                            "matched": rule_list["matched"],
                            "first_failed_rule": rule_list["first_failed_rule"],
                            "rules": [
                                {
                                    "name": rule["name"],
                                    "arguments": _serialize_rule_arguments(
                                        rule["arguments"]
                                    ),
                                    "passed": rule["passed"],
                                }
                                for rule in rule_list["rules"]
                            ],
                        }
                        for rule_list in path_diagnostic.get("rule_lists", [])
                    ],
                },
                "exploit_candidates": _serialize_exploit_reports(exploit_reports),
            }
        )

    if G.check_proto_pollution:
        for index, node_id in enumerate(sorted(G.proto_pollution), start=1):
            findings.append(
                {
                    "id": f"jsflow/proto_pollution/{index}",
                    "rule_id": "jsflow/proto_pollution",
                    "status": "matched",
                    "message": _build_message("matched"),
                    "source": None,
                    "sink": _node_record(G, node_id),
                    "poc": None,
                    "poc_guidance": None,
                    "path": None,
                    "rule_evaluation": {
                        "matched": True,
                        "matched_rule_list": None,
                        "rule_lists": [],
                    },
                    "exploit_candidates": [],
                }
            )

    if G.check_ipt:
        for index, node_id in enumerate(sorted(G.ipt_use), start=1):
            findings.append(
                {
                    "id": f"jsflow/int_prop_tampering/{index}",
                    "rule_id": "jsflow/int_prop_tampering",
                    "status": "matched",
                    "message": _build_message("matched"),
                    "source": _node_record(G, next(iter(sorted(G.ipt_write)), None)),
                    "sink": _node_record(G, node_id),
                    "poc": None,
                    "poc_guidance": None,
                    "path": None,
                    "rule_evaluation": {
                        "matched": True,
                        "matched_rule_list": None,
                        "rule_lists": [],
                    },
                    "exploit_candidates": [],
                }
            )

    started_dt = datetime.fromtimestamp(started_at, timezone.utc)
    report = {
        "$schema": REPORT_SCHEMA,
        "version": REPORT_VERSION,
        "tool": {
            "name": "jsflow",
        },
        "run": {
            "input_file": getattr(args, "input_file", None),
            "entry_file": G.entry_file_path,
            "vulnerability_type": G.vul_type,
            "module_mode": bool(getattr(args, "module", False)),
            "auto_exploit": bool(G.auto_exploit),
            "started_at": started_dt.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "log_dir": G.log_dir,
        },
        "summary": {
            "detection_status": "successful" if G.success_detect else "failed",
            "exploit_status": (
                "successful"
                if G.success_exploit
                else ("failed" if G.auto_exploit else "turned_off")
            ),
            "candidate_paths": len(candidate_paths),
            "matched_findings": sum(1 for finding in findings if finding["status"] == "matched"),
            "total_findings": len(findings),
            "vulnerable_files": sorted(
                os.path.relpath(path, G.entry_file_path)
                for path in G.vul_files
            )
            if G.entry_file_path
            else sorted(G.vul_files),
            "covered_statements": len(getattr(G, "covered_stat", [])),
            "total_statements": _safe_method(G, "get_total_num_statements", default=None),
            "covered_functions": len(getattr(G, "covered_func", [])),
            "total_functions": _safe_method(G, "get_total_num_functions", default=None),
            "num_cf_paths": getattr(G, "num_of_cf_paths", None),
            "num_prec_cf_paths": getattr(G, "num_of_prec_cf_paths", None),
            "num_full_cf_paths": getattr(G, "num_of_full_cf_paths", None),
            "reruns": getattr(G, "rerun_counter", None),
        },
        "exploit_results": _serialize_exploit_reports(exploit_reports),
        "findings": findings,
    }
    return report


def write_reports(report, output_dir, *, emit_json=False):
    os.makedirs(output_dir, exist_ok=True)
    written = {}
    schema_src = os.path.join(os.path.dirname(__file__), "report.schema.json")
    schema_dst = os.path.join(output_dir, "report.schema.json")
    if os.path.exists(schema_src):
        with open(schema_src, "r", encoding="utf-8") as src_handle:
            schema_text = src_handle.read()
        with open(schema_dst, "w", encoding="utf-8") as dst_handle:
            dst_handle.write(schema_text)
        written["schema"] = schema_dst
    if emit_json:
        json_path = os.path.join(output_dir, "report.json")
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        written["json"] = json_path
    return written
