"""
Runtime setup for the JavaScript parser dependency.

On first use, copies the bundled parser scripts (``probejs/_parser/``) to a
user-writable cache directory and runs ``npm install``. Subsequent runs reuse
the cached copy.

Design rationale
----------------
The Python package ships the JavaScript source files for the AST parser as
package data, but it does **not** ship the npm ``node_modules/`` tree.
Shipping 25 MB of minified JavaScript (especially the TypeScript compiler)
in the wheel is feasible but wasteful when many users may only parse plain
JavaScript. More importantly, npm packages are platform-independent and
should be installed by npm, not by pip.

The approach mirrors `playwright <https://playwright.dev/>`_'s browser
download: the first call to any parsing function triggers a one-time setup
that copies the scripts to ``~/.cache/probejs/parser/`` and runs
``npm install`` there. The :ref:`probejs-setup` CLI command lets users run
this step explicitly ahead of time.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "probejs"
_PARSER_PACKAGE_DIR = Path(__file__).resolve().parent / "_parser"
_BUILTIN_PACKAGES_SRC = Path(__file__).resolve().parent / "builtin_packages"

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_parser_dir() -> Path:
    """Return the path to a ready-to-use parser directory.

    If the parser has not been set up yet, this function copies the bundled
    scripts to ``~/.cache/probejs/parser/`` and runs ``npm install``.
    """
    # A source checkout may already have its npm dependencies installed. Using
    # it directly keeps editable installs synchronized with parser source
    # changes instead of accidentally running a stale user-cache copy.
    if (_PARSER_PACKAGE_DIR / "node_modules").is_dir():
        return _PARSER_PACKAGE_DIR

    cached = CACHE_DIR / "parser"

    if cached.exists() and (cached / "node_modules").exists():
        source_package = _PARSER_PACKAGE_DIR / "package.json"
        cached_package = cached / "package.json"
        required_scripts = [cached / "main.js", cached / "typescript-main.js"]
        if (
            source_package.is_file()
            and cached_package.is_file()
            and source_package.read_bytes() == cached_package.read_bytes()
            and all(script.is_file() for script in required_scripts)
        ):
            return cached

    return _install_parser(cached)


def install_parser(*, force: bool = False) -> Path:
    """Explicitly install (or reinstall) the JavaScript parser.

    Args:
        force: If ``True``, re-copy the scripts and re-run ``npm install``
            even if the cache already exists.

    Returns:
        Path to the installed parser directory.
    """
    cached = CACHE_DIR / "parser"

    if force and cached.exists():
        shutil.rmtree(cached)

    return _install_parser(cached)


def is_installed() -> bool:
    """Check whether the parser is already installed."""
    cached = CACHE_DIR / "parser"
    return cached.exists() and (cached / "node_modules").exists()


# ---------------------------------------------------------------------------
# CLI (``python -m probejs setup``)
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for ``probejs setup``."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Install the JavaScript parser dependencies for probejs."
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Reinstall even if the parser is already set up.",
    )
    args = parser.parse_args()

    if is_installed() and not args.force:
        print(
            "[probejs] JavaScript parser is already installed "
            f"at {CACHE_DIR / 'parser'}",
            file=sys.stderr,
        )
        print("[probejs] Use --force to reinstall.", file=sys.stderr)
        return

    path = install_parser(force=args.force)
    print(f"[probejs] JavaScript parser ready at {path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def get_builtin_packages_dir() -> Path:
    """Return the path to the JS-modeled built-in module stubs, installing to
    a user-writable cache on first use so the JS parser find them via walk-up.
    """
    cached = CACHE_DIR / "builtin_packages"

    if not cached.exists():
        if _BUILTIN_PACKAGES_SRC.is_dir():
            shutil.copytree(_BUILTIN_PACKAGES_SRC, cached)
        else:
            return _BUILTIN_PACKAGES_SRC

    return cached


def _install_parser(dest: Path) -> Path:
    """Copy parser scripts to *dest* and run ``npm install``."""
    src = _find_parser_source()

    if dest.exists():
        shutil.rmtree(dest)

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        src,
        dest,
        # Never copy stale node_modules from a dev checkout.
        ignore=shutil.ignore_patterns("node_modules"),
    )

    print("[probejs] Installing JavaScript parser dependencies ...", file=sys.stderr)
    result = subprocess.run(
        ["npm", "install"],
        cwd=str(dest),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(
            "[probejs] WARNING: npm install exited with code "
            f"{result.returncode}. stderr:\n{result.stderr}",
            file=sys.stderr,
        )
        print(
            "[probejs] Make sure Node.js and npm are installed and "
            "available on your PATH.",
            file=sys.stderr,
        )
    else:
        print("[probejs] JavaScript parser ready.", file=sys.stderr)

    return dest


def _find_parser_source() -> Path:
    """Find the bundled parser source directory.

    Priority:
    1. ``probejs/_parser/`` (normal installed / editable mode)
    2. Repository root ``esprima-csv/`` (fallback for legacy checkouts)
    """
    if _PARSER_PACKAGE_DIR.is_dir():
        return _PARSER_PACKAGE_DIR

    # Legacy fallback: if the user still has esprima-csv/ at the repo root.
    legacy = Path(os.getcwd()) / "esprima-csv"
    if legacy.is_dir():
        return legacy

    raise RuntimeError(
        "Could not find the bundled JavaScript parser scripts. "
        "Your probejs installation may be corrupted.\n"
        f"Expected to find 'probejs/_parser/' but it does not exist at:\n"
        f"  {_PARSER_PACKAGE_DIR}"
    )


if __name__ == "__main__":
    main()
