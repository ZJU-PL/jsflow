"""
Helpers for invoking the bundled Esprima-based parsing scripts.

This module is the Python bridge to the small Node.js utilities in
`esprima-csv/`. `opgen` uses these helpers to:

- parse JavaScript into the CSV/AST form consumed by probejs
- resolve Node-style module entry points
- discover the transitive file set loaded by a `require(...)`

The functions here intentionally stay thin: they delegate parsing and module
resolution to the maintained JavaScript side and only normalize the results for
the Python analysis pipeline.
"""

import os
import subprocess
import re

main_js_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "../../esprima-csv/main.js")
)
search_js_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "../../esprima-csv/search.js")
)


def esprima_parse(path="-", args=[], input=None, print_func=print):
    """Run the Esprima CSV parser and return its stdout payload.

    Args:
        path: File path to parse, or `-` to read source from stdin.
        args: Extra CLI flags forwarded to `esprima-csv/main.js`.
        input: Optional source text when parsing from stdin.
        print_func: Sink for parser stderr, typically the probejs logger.

    Returns:
        The parser stdout as a string. The caller is responsible for decoding
        the emitted CSV/AST format.
    """
    # use "universal_newlines" instead of "text" if you're using Python <3.7
    #        ↓ ignore this error if your editor shows
    proc = subprocess.Popen(
        ["node", main_js_path, path] + args,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(input)
    print_func(stderr)
    return stdout


def esprima_search(module_name, search_path, print_func=print, disable_builtin_packages=False):
    """Resolve a module import using the bundled Node-side resolver.

    The search helper mirrors Node-style resolution closely enough for probejs's
    module analysis. It returns both the discovered main file and the resolved
    module directory so `opgen` can analyze the right entry point.
    """
    cmd = ["node", search_js_path]
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
    """Return files touched when Node evaluates `require(module_name)`.

    The underlying script writes progress information to stderr. This helper
    strips ANSI color codes and extracts only the emitted "Analyzing ..." file
    paths so tests and higher-level tooling can reason about the module closure.
    """
    script = "var main_func=require('{}');".format(module_name)
    # use "universal_newlines" instead of "text" if you're using Python <3.7
    #        ↓ ignore this error if your editor shows
    proc = subprocess.Popen(
        ["node", main_js_path, "-", "-o", "-"],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(script)
    file_list = []
    for line in stderr.splitlines():
        # Strip ANSI color codes and surrounding markers.
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
