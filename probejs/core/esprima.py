"""
Helpers for dispatching to the bundled JavaScript and TypeScript frontends.

This module is the Python bridge to the small Node.js utilities shipped in
``probejs/_parser/``.  ``opgen`` uses these helpers to:

- parse JavaScript and TypeScript into the shared CSV/AST form consumed by probejs
- resolve Node-style and tsconfig-aware module entry points
- discover the transitive file set loaded by a ``require(...)``

Parser lifecycle
----------------
The JavaScript scripts are shipped as package data but their npm dependencies
(``esprima``, ``typescript``, ``typescript-estree``, …) are **not** bundled in the wheel. On the
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

# Source locations retained for callers and tests that inspect the bundled
# parser assets. Runtime execution still goes through the lazy cache helpers.
main_js_path = str(Path(__file__).resolve().parent.parent / "_parser" / "main.js")
typescript_main_js_path = str(
    Path(__file__).resolve().parent.parent / "_parser" / "typescript-main.js"
)
search_js_path = str(Path(__file__).resolve().parent.parent / "_parser" / "search.js")


def _ensure_parser() -> Path:
    """Return the parser directory, setting it up on first call."""
    global _parser_dir
    if _parser_dir is None:
        _parser_dir = get_parser_dir()
    return _parser_dir


def _main_js() -> str:
    return str(_ensure_parser() / "main.js")


def _typescript_main_js() -> str:
    return str(_ensure_parser() / "typescript-main.js")


def _search_js() -> str:
    return str(_ensure_parser() / "search.js")


def _directory_contains_typescript(directory: Path) -> bool:
    """Return whether *directory* contains a runtime TypeScript source file."""
    skipped = {"node_modules", ".git", "dist", "build", "coverage"}
    for root, directories, files in os.walk(directory):
        directories[:] = [name for name in directories if name not in skipped]
        for name in files:
            lower = name.lower()
            if lower.endswith((".d.ts", ".d.mts", ".d.cts")):
                continue
            if Path(name).suffix.lower() in {".ts", ".tsx", ".mts", ".cts"}:
                return True
    return False


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def esprima_parse(path="-", args=None, input=None, print_func=print):
    """Run the appropriate JavaScript or TypeScript frontend.

    Args:
        path: File path to parse, or ``-`` to read source from stdin.
        args: Extra CLI flags forwarded to the selected Node frontend.
        input: Optional source text when parsing from stdin.
        print_func: Sink for parser stderr, typically the probejs logger.

    Returns:
        The parser stdout as a string. The caller is responsible for decoding
        the emitted CSV/AST format.
    """
    if args is None:
        args = []
    use_typescript = "--typescript" in args
    if path != "-":
        candidate = Path(path)
        if candidate.suffix.lower() == ".ets":
            raise RuntimeError(
                "ArkTS .ets input is not supported by the TypeScript frontend; "
                "analyze JavaScript produced by the HarmonyOS toolchain instead"
            )
        if candidate.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"}:
            use_typescript = True
        elif candidate.is_dir():
            use_typescript = _directory_contains_typescript(candidate)
    parser_script = _typescript_main_js() if use_typescript else _main_js()
    proc = subprocess.Popen(
        ["node", parser_script, path] + args,
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
