"""Staged evidence assembly for PoC generation prompts."""

from __future__ import annotations

import json
from os import PathLike
from collections.abc import Mapping
from typing import Any


def evidence_for_stage(
    finding: dict[str, Any],
    *,
    stage: int,
    max_chars: int = 30_000,
) -> dict[str, Any]:
    """Return progressively larger evidence for retry stage.

    Stage 0 intentionally returns no extra evidence; the agent should use only
    the compact packet. Later stages reveal selected proof data.
    """
    poc = finding.get("poc") if isinstance(finding.get("poc"), dict) else {}
    if stage <= 0:
        return {"stage": 0, "contents": {}}
    if stage == 1:
        contents = {
            "thin_slice": poc.get("thin_slice"),
            "payload_contract": poc.get("payload_contract"),
            "validation_oracle": poc.get("validation_oracle"),
        }
    elif stage == 2:
        contents = {
            "trace": poc.get("trace"),
            "path": finding.get("path"),
            "rule_evaluation": finding.get("rule_evaluation"),
            "exploit_candidates": finding.get("exploit_candidates"),
        }
    else:
        contents = {"finding": finding}

    return {
        "stage": stage,
        "contents": _truncate_jsonable(contents, max_chars=max_chars),
    }


def render_json(data: Any, *, max_chars: int = 30_000) -> str:
    text = dumps_json(data)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated] ..."


def _truncate_jsonable(data: Any, *, max_chars: int) -> Any:
    text = dumps_json(data)
    if len(text) <= max_chars:
        return data
    return {
        "truncated": True,
        "max_chars": max_chars,
        "json_prefix": text[:max_chars],
    }


def dumps_json(data: Any) -> str:
    return json.dumps(to_jsonable(data), indent=2, sort_keys=True)


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, set):
        return [to_jsonable(item) for item in sorted(value, key=str)]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    if isinstance(value, PathLike):
        return str(value)
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def json_default(value: Any) -> Any:
    return to_jsonable(value)
