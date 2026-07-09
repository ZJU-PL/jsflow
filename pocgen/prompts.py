"""Prompt template loading for pocgen."""

from __future__ import annotations

from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


def load(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def render(name: str, **kwargs) -> str:
    return load(name).format(**kwargs)

