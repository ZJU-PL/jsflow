"""
Helpers for invoking the bundled JavaScript/TypeScript parsing scripts.

This module is the Python bridge to the small Node.js utilities shipped in
``probejs/_parser/``.  ``opgen`` uses these helpers to:

- parse JavaScript and TypeScript into the CSV/AST form consumed by probejs
- resolve Node-style and tsconfig-aware module entry points
- discover the transitive file set loaded by a ``require(...)``

Parser lifecycle
----------------
The JavaScript scripts are shipped as package data but their npm dependencies
(``esprima``, ``typescript``, …) are **not** bundled in the wheel.  On the
first call to any function in this module, :func:`probejs._setup.get_parser_dir`
copies the scripts to ``~/.cache/probejs/parser/`` and runs ``npm install``.
Subsequent calls reuse the cached copy.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from probejs._setup import get_parser_dir

# ---------------------------------------------------------------------------
# Lazy initialisation helpers
# ---------------------------------------------------------------------------

_parser_dir: Path | None = None


def _ensure_parser() -> Path:
    """Return the parser directory, setting it up on first call."""
    global _parser_dir
    if _parser_dir is None:
        _parser_dir = get_parser_dir()
    return _parser_dir


def _main_js() -> str:
    return str(_ensure_parser() / "main.js")


def _search_js() -> str:
    return str(_ensure_parser() / "search.js")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def esprima_parse(path="-", args=None, input=None, print_func=print):
    """Run the JavaScript/TypeScript CSV parser and return its stdout payload.

    Args:
        path: File path to parse, or ``-`` to read source from stdin.
        args: Extra CLI flags forwarded to ``probejs/_parser/main.js``.
        input: Optional source text when parsing from stdin.
        print_func: Sink for parser stderr, typically the probejs logger.

    Returns:
        The parser stdout as a string. The caller is responsible for decoding
        the emitted CSV/AST format.
    """
    if args is None:
        args = []
    proc = subprocess.Popen(
        ["node", _main_js(), path] + args,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(input)
    print_func(stderr)
    if isinstance(proc.returncode, int) and proc.returncode != 0:
        raise RuntimeError(
            "JavaScript/TypeScript parsing failed for {}:\n{}".format(path, stderr.strip())
        )
    return stdout


def esprima_search(module_name, search_path, print_func=print, disable_builtin_packages=False):
    """Resolve a module import using the bundled Node-side resolver.

    The search helper mirrors Node-style resolution closely enough for probejs's
    module analysis. It returns both the discovered main file and the resolved
    module directory so ``opgen`` can analyse the right entry point.
    """
    cmd = ["node", _search_js()]
    if disable_builtin_packages:
        cmd.append("--no-builtin-packages")
    cmd.extend([module_name, search_path])
    proc = subprocess.Popen(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    print_func(stderr)
    main_path, module_path = stdout.split("\n")[:2]
    return main_path, module_path


def get_file_list(module_name):
    """Return files touched when Node evaluates ``require(module_name)``.

    The underlying script writes progress information to stderr. This helper
    strips ANSI colour codes and extracts only the emitted "Analyzing …" file
    paths so tests and higher-level tooling can reason about the module closure.
    """
    script = "var main_func=require('{}');".format(module_name)
    proc = subprocess.Popen(
        ["node", _main_js(), "-", "-o", "-"],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(script)
    file_list = []
    for line in stderr.splitlines():
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if clean.startswith("["):
            clean = clean[1:].strip()
        if clean.endswith("]"):
            clean = clean[:-1].strip()
        if clean.startswith("Analyzing "):
            file_path = clean[len("Analyzing ") :].strip()
            if file_path != "stdin":
                file_list.append(file_path)
    return file_list
