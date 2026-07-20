"""Structured JSON reporting helpers for probejs analysis runs."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .vuln.vul_checking import get_path_text
REPORT_SCHEMA = "./report.schema.json"
REPORT_VERSION = "1.3.0"
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
        return "probejs matched vulnerability rules for this path."
    if status == "exploit_only":
        return "probejs solved exploit-like payloads for this path, but rule matching failed."
    return "probejs found a candidate path that did not satisfy all rules."


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
            "reason": f"Recovered from probejs exploit result status={status}",
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


def _line_role(index: int, total: int) -> str:
    if index == 0:
        return "source"
    if index == total - 1:
        return "sink"
    return "propagation"


def _build_hybrid_thin_slice(path_nodes, source_node, sink_node, path_text: str) -> dict:
    spans = []
    seen = set()
    visible_nodes = [node for node in path_nodes if node]
    total = len(visible_nodes)
    for index, node in enumerate(visible_nodes):
        file_path = node.get("file")
        line = node.get("line")
        key = (file_path, line, node.get("end_line"), node.get("code"))
        if key in seen:
            continue
        seen.add(key)
        spans.append(
            {
                "file": file_path,
                "start_line": line,
                "end_line": node.get("end_line") or line,
                "role": _line_role(index, total),
                "symbol": node.get("function"),
                "code": node.get("code"),
            }
        )

    source_code = (source_node or {}).get("code") or (source_node or {}).get("function")
    sink_code = (sink_node or {}).get("code") or (sink_node or {}).get("function")
    data_dependencies = []
    if source_code and sink_code:
        data_dependencies.append(f"{source_code} -> {sink_code}")
    elif source_code:
        data_dependencies.append(str(source_code))
    elif sink_code:
        data_dependencies.append(str(sink_code))

    return {
        "kind": "hybrid_thin_slice",
        "graph_slice": {
            "node_ids": [node.get("id") for node in visible_nodes],
            "edge_focus": ["OBJ_REACHES", "CONTRIBUTES_TO", "CALLS"],
            "source_node_id": (source_node or {}).get("id"),
            "sink_node_id": (sink_node or {}).get("id"),
        },
        "source_slice": {
            "required_spans": spans,
            "path_text": path_text,
            "irrelevant_spans_removed": True,
        },
        "runtime_slice": {
            "entrypoint_needed": True,
            "mock_sink_recommended": True,
            "control_dependencies": [],
            "data_dependencies": data_dependencies,
        },
    }


def _load_package_json(package_root: str) -> dict:
    if not package_root:
        return {}
    package_json = Path(package_root) / "package.json"
    if not package_json.exists():
        return {}
    try:
        return json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _package_manager_hint(package_root: str) -> str:
    if not package_root:
        return "unknown"
    root = Path(package_root)
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "yarn.lock").exists():
        return "yarn"
    if (root / "package-lock.json").exists():
        return "npm"
    if (root / "bun.lockb").exists() or (root / "bun.lock").exists():
        return "bun"
    return "npm" if (root / "package.json").exists() else "unknown"


def _install_command(package_manager: str) -> str:
    return {
        "npm": "npm install",
        "yarn": "yarn install",
        "pnpm": "pnpm install",
        "bun": "bun install",
    }.get(package_manager, "")


def _mock_recommendations(vul_type: str, sink_record: dict) -> list[str]:
    symbol = str((sink_record or {}).get("symbol") or "")
    if vul_type == "os_command" or "child_process" in symbol:
        return ["child_process.exec", "child_process.execSync", "child_process.spawn"]
    if vul_type == "path_traversal" or symbol.startswith("fs."):
        return ["fs.readFile", "fs.readFileSync"]
    if vul_type == "nosql":
        return ["mongodb collection query method"]
    if vul_type == "xss":
        return ["response send/write/end method"]
    if vul_type == "code_exec":
        return ["eval", "Function", "console.log"]
    return []


def _runtime_environment(package_root: str, entry_file: str, vul_type: str, sink_record: dict) -> dict:
    package = _load_package_json(package_root)
    package_manager = _package_manager_hint(package_root)
    scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
    engines = package.get("engines") if isinstance(package.get("engines"), dict) else {}
    required_files = []
    if entry_file:
        required_files.append(entry_file)
    if package:
        required_files.append("package.json")
    return {
        "cwd": package_root,
        "package_manager": package_manager,
        "install_command": _install_command(package_manager),
        "node_version_hint": engines.get("node") or "unknown",
        "needs_build": "build" in scripts,
        "build_command": f"{package_manager} run build" if "build" in scripts and package_manager != "unknown" else "",
        "required_files": required_files,
        "external_services": ["mongodb"] if vul_type == "nosql" else [],
        "mock_recommended": _mock_recommendations(vul_type, sink_record),
        "notes": "Prefer mocks for dangerous or external side effects when validating PoCs.",
    }


def _entrypoint_contract(export_metadata: dict, candidate_calls: list[str], payload_candidates: list[dict], entry_text: str) -> dict:
    payload_example = (
        payload_candidates[0].get("candidate")
        if payload_candidates
        else "PAYLOAD"
    )
    return {
        "module_system": _infer_export_style(entry_text),
        "require_path": "",
        "call_shapes": candidate_calls,
        "preferred_call": candidate_calls[0] if candidate_calls else "",
        "argument_schema": {
            "type": "unknown",
            "tainted_argument": {
                "symbol": export_metadata["source_symbol"],
                "example": payload_example,
            },
        },
        "async": {
            "kind": "unknown",
            "settle_strategy": "Run synchronously first; await returned Promise or callback if runtime behavior requires it.",
        },
    }


def _payload_sink_expectation(vul_type: str) -> str:
    return {
        "os_command": "Command argument reaches a child_process shell/command sink with the marker payload intact.",
        "code_exec": "Payload reaches eval/Function-like code execution sink as executable JavaScript.",
        "path_traversal": "Path argument preserves traversal marker when it reaches the filesystem sink.",
        "xss": "Payload reaches response body or header without output encoding.",
        "nosql": "Payload reaches database query construction without operator/key sanitization.",
    }.get(vul_type, "Payload reaches the reported sink without an effective sanitizer.")


def _payload_contract(G, payload_candidates: list[dict], path_nodes, sink_record: dict) -> dict:
    best = payload_candidates[0] if payload_candidates else {}
    trace_codes = []
    for node in path_nodes:
        code = (node or {}).get("code")
        if code and code not in trace_codes:
            trace_codes.append(code)
    constraints = []
    if payload_candidates:
        constraints.append("Use a payload candidate recovered from probejs exploit solving.")
    else:
        constraints.append("No concrete solver payload was recovered; choose a short marker payload for the vulnerability class.")
    constraints.append("Place the payload in the tainted source binding, not directly at the sink.")
    return {
        "source_binding": best.get("input") or "input",
        "payload": best.get("candidate"),
        "sink": sink_record,
        "sink_expectation": _payload_sink_expectation(G.vul_type),
        "constraints": constraints,
        "transform_chain": trace_codes,
    }


def _validation_oracle(vul_type: str, payload_candidates: list[dict], sink_record: dict) -> dict:
    fallback = _recover_oracle(vul_type, payload_candidates)
    symbol = (sink_record or {}).get("symbol") or "reported sink"
    preferred = {
        "type": "mock_sink_call",
        "sink_symbol": symbol,
        "assertion": f"Intercept {symbol} and assert one argument contains the payload marker.",
        "notes": "Mocking the sink is safer and usually more stable than executing the side effect.",
    }
    if vul_type == "xss":
        preferred = {
            "type": "response_contains",
            "sink_symbol": symbol,
            "assertion": "Assert the response body/header contains the marker unescaped.",
            "notes": "A mocked response object can capture send/write/end arguments.",
        }
    elif vul_type == "path_traversal":
        preferred = {
            "type": "mock_fs_call",
            "sink_symbol": symbol,
            "assertion": "Intercept the filesystem call and assert the path contains traversal segments.",
            "notes": "Prefer mocking fs over reading arbitrary local files.",
        }
    elif vul_type == "nosql":
        preferred = {
            "type": "mock_database_query",
            "sink_symbol": symbol,
            "assertion": "Intercept the query call and assert the query object contains the injected marker/operator.",
            "notes": "Prefer a fake collection over starting a database service.",
        }
    return {
        "preferred": preferred,
        "fallback": fallback,
    }


def _recommended_harness(export_style: str, vul_type: str, runtime_environment: dict) -> dict:
    if export_style == "esm":
        template = "esm-import.mjs.template"
    elif vul_type == "proto_pollution":
        template = "proto-poc.cjs.template"
    else:
        template = "direct-call.cjs.template"
    mock_targets = runtime_environment.get("mock_recommended", [])
    return {
        "template": template,
        "reason": "Selected from module style and vulnerability type.",
        "mock_strategy": (
            f"Monkeypatch {', '.join(mock_targets)} before invoking the target."
            if mock_targets
            else "Use a direct call harness and assert the returned value or captured side effect."
        ),
    }


def _agent_todo(poc: dict) -> list[str]:
    todo = [
        "Create a minimal PoC file in the package root.",
        f"Load the target with {poc['target']['require_path'] or 'the recovered entry file'}.",
    ]
    mocks = poc.get("runtime_environment", {}).get("mock_recommended", [])
    if mocks:
        todo.append(f"Install a mock for {', '.join(mocks)} before the vulnerable code runs.")
    preferred_call = poc.get("entrypoint_contract", {}).get("preferred_call")
    if preferred_call:
        todo.append(f"Invoke the target using `{preferred_call}` with the payload in the tainted argument.")
    else:
        todo.append("Try the candidate call shapes and keep the smallest one that reaches the sink.")
    todo.append("Assert the validation oracle and print PASS only when it fires.")
    return todo


def _agent_packet(poc: dict) -> dict:
    """Compact handoff intended to be pasted directly into a coding agent."""
    spans = poc.get("thin_slice", {}).get("source_slice", {}).get("required_spans", [])
    compact_spans = [
        {
            "file": span.get("file"),
            "line": span.get("start_line"),
            "role": span.get("role"),
            "code": span.get("code"),
        }
        for span in spans[:6]
    ]
    payload_candidates = poc.get("constraints", {}).get("payload_candidates", [])
    payload = payload_candidates[0].get("candidate") if payload_candidates else None
    return {
        "purpose": "Generate the smallest safe PoC harness for this probejs finding.",
        "finding_id": poc.get("finding_id"),
        "vulnerability_type": poc.get("vulnerability_type"),
        "target": {
            "cwd": poc.get("runtime_environment", {}).get("cwd"),
            "require_path": poc.get("target", {}).get("require_path"),
            "module_system": poc.get("entrypoint_contract", {}).get("module_system"),
            "preferred_call": poc.get("entrypoint_contract", {}).get("preferred_call"),
        },
        "payload": {
            "source_binding": poc.get("payload_contract", {}).get("source_binding"),
            "candidate": payload,
            "expectation": poc.get("payload_contract", {}).get("sink_expectation"),
        },
        "sink": poc.get("sink"),
        "validation": poc.get("validation_oracle", {}).get("preferred"),
        "runtime": {
            "mock_recommended": poc.get("runtime_environment", {}).get("mock_recommended", []),
            "external_services": poc.get("runtime_environment", {}).get("external_services", []),
            "install_command": poc.get("runtime_environment", {}).get("install_command", ""),
            "build_command": poc.get("runtime_environment", {}).get("build_command", ""),
        },
        "thin_slice_summary": compact_spans,
        "recommended_harness": poc.get("recommended_harness"),
        "todo": poc.get("agent_todo", []),
        "uncertainty": poc.get("known_uncertainties", [])[:3],
    }


def _confidence_and_uncertainty(export_metadata: dict, payload_candidates: list[dict], source_node, sink_node, entry_text: str) -> tuple[dict, list[str]]:
    payload_status = "high" if any(p.get("reason", "").endswith("status=solved") for p in payload_candidates) else ("medium" if payload_candidates else "low")
    entry_confidence = "medium" if export_metadata["exported_symbol_kind"] != "unknown" else "low"
    confidence = {
        "source": "high" if source_node else "low",
        "sink": "high" if sink_node else "low",
        "entrypoint": entry_confidence,
        "payload": payload_status,
        "overall": "medium" if payload_status != "low" and sink_node else "low",
    }
    uncertainties = []
    if export_metadata["exported_symbol_kind"] == "unknown":
        uncertainties.append("Entry point export shape was not recovered from module.exports/exports syntax.")
    if not payload_candidates:
        uncertainties.append("No solved payload candidate was available; PoC author must choose a marker payload.")
    if not entry_text:
        uncertainties.append("Entry file text was unavailable, so call shape and package metadata are heuristic.")
    uncertainties.append("Async behavior is not proven statically; adjust the harness if the call returns a Promise or requires a callback.")
    return confidence, uncertainties


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
    thin_slice = _build_hybrid_thin_slice(path_nodes, source_node, sink_node, path_text)
    entrypoint_contract = _entrypoint_contract(
        export_metadata, candidate_calls, payload_candidates, entry_text
    )
    entrypoint_contract["require_path"] = require_path
    runtime_environment = _runtime_environment(
        package_root, entry_path.name if entry_path else "", G.vul_type, sink_record
    )
    validation_oracle = _validation_oracle(G.vul_type, payload_candidates, sink_record)
    payload_contract = _payload_contract(G, payload_candidates, path_nodes, sink_record)
    recommended_harness = _recommended_harness(
        _infer_export_style(entry_text), G.vul_type, runtime_environment
    )
    confidence, uncertainties = _confidence_and_uncertainty(
        export_metadata, payload_candidates, source_node, sink_node, entry_text
    )

    poc = {
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
        "thin_slice": thin_slice,
        "entrypoint_contract": entrypoint_contract,
        "payload_contract": payload_contract,
        "validation_oracle": validation_oracle,
        "runtime_environment": runtime_environment,
        "recommended_harness": recommended_harness,
        "confidence": confidence,
        "known_uncertainties": uncertainties,
        "environment": {
            "cwd": package_root,
            "notes": "Recovered from canonical probejs report output.",
        },
        "validation": {
            "status": "not_run",
            "run_command": "",
            "observed_output": "",
        },
        "raw_probejs": {
            "report_finding_id": finding_id,
            "report_message": status_message,
            "report_log_dir": getattr(G, "log_dir", None),
        },
        "assumptions": [
            "Recovered from canonical probejs report output.",
            "Prefer probejs-recovered PoC fields over downstream re-inference.",
        ],
    }
    poc["agent_todo"] = _agent_todo(poc)
    poc["agent_packet"] = _agent_packet(poc)
    return poc


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
        "thin_slice": poc["thin_slice"],
        "entrypoint_contract": poc["entrypoint_contract"],
        "payload_contract": poc["payload_contract"],
        "validation_oracle": poc["validation_oracle"],
        "runtime_environment": poc["runtime_environment"],
        "recommended_harness": poc["recommended_harness"],
        "agent_todo": poc["agent_todo"],
        "agent_packet": poc["agent_packet"],
        "confidence": poc["confidence"],
        "known_uncertainties": poc["known_uncertainties"],
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
        finding_id = f"probejs/{G.vul_type}/{index + 1}"
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
                "rule_id": f"probejs/{G.vul_type}",
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
                    "id": f"probejs/proto_pollution/{index}",
                    "rule_id": "probejs/proto_pollution",
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
                    "id": f"probejs/int_prop_tampering/{index}",
                    "rule_id": "probejs/int_prop_tampering",
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
            "name": "probejs",
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
            "frontend_diagnostics": len(getattr(G, "frontend_diagnostics", [])),
            "frontend_errors": sum(
                1
                for diagnostic in getattr(G, "frontend_diagnostics", [])
                if diagnostic.get("category") == "error"
            ),
        },
        "frontend": {
            "compilers": getattr(G, "frontend_compilers", []),
            "diagnostics": getattr(G, "frontend_diagnostics", []),
            "arkts_projects": getattr(G, "arkts_projects", []),
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
