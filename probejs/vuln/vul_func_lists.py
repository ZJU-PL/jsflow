"""
Vulnerable Function Signatures - Sink definitions for vulnerability detection.

This module defines the lists of function signatures (sinks) that are used to
identify potential vulnerabilities during analysis. Each vulnerability type has
its own set of sink functions that, when reached by tainted user input, indicate
a security vulnerability.

Sink Naming Convention:
-----------------------
- sink_hqbpillvul_*: These are special sink markers inserted by the builtin
  package models (in builtin_packages/*.js). They mark the exact point where
  user input would be dangerous.
- Regular function names (e.g., "eval", "Function"): These are native JavaScript
  functions that are inherently dangerous when processing user input.
- Method patterns (e.g., "res.send", "fs.readFile"): These are common patterns
  from popular libraries like Express.js and Node.js built-ins.

Vulnerability Types:
-------------------
- os_command: OS command injection (CWE-78) - user input reaches shell commands
- xss: Cross-site scripting (CWE-79) - user input reaches HTTP response
- code_exec: Code injection (CWE-94) - user input reaches eval/Function
- proto_pollution: Prototype pollution (CWE-1321) - user input modifies prototypes
- path_traversal: Path traversal (CWE-22) - user input reaches file operations
- nosql: NoSQL injection (CWE-943) - user input reaches database queries
- sanitation: Functions that sanitize input (exclude from vulnerable paths)
"""

signature_lists = {
    "os_command": [
        "sink_hqbpillvul_execFile",
        "sink_hqbpillvul_exec",
        "sink_hqbpillvul_execSync",
        "sink_hqbpillvul_spawn",
        "sink_hqbpillvul_spawnSync",
        "sink_hqbpillvul_execa_shell",
        "sink_hqbpillvul_shelljs_exec",
    ],
    "os_command_strict": [
        "sink_hqbpillvul_exec",
        "sink_hqbpillvul_execSync",
        "sink_hqbpillvul_execa_shell",
        "sink_hqbpillvul_shelljs_exec",
    ],
    # XSS sinks (http response emission)
    # - sink_hqbpillvul_* are modeled sinks used by builtin stubs
    # - res.send/write/end are common Express/Node patterns that may appear
    #   as dummy function names in graphs when the response object is a wildcard
    "xss": [
        "sink_hqbpillvul_http_write",
        "sink_hqbpillvul_http_setHeader",
        "res.send",
        "res.write",
        "res.end",
    ],
    # Prototype pollution "goal" function names used by rough call graph pruning.
    # This list is intentionally broad: real-world prototype pollution commonly
    # flows through deep-merge / deep-set helpers rather than explicit writes
    # to built-in prototypes.
    "proto_pollution": [
        "merge",
        "extend",
        "assign",
        "defaultsDeep",
        "defaultsdeep",
        "set",
        "setWith",
        "setwith",
        "clone",
        "parse",
    ],
    "code_exec": [
        "Function",
        "eval",
        # "sink_hqbpillvul_execFile",
        # 'sink_hqbpillvul_exec',
        # 'sink_hqbpillvul_execSync',
        "sink_hqbpillvul_eval",
    ],
    # NoSQL sinks. In modeled MongoDB stubs we emit sink_hqbpillvul_nosql; in
    # simple samples (e.g. tests) the query API can show up directly as `find`.
    "nosql": ["sink_hqbpillvul_nosql", "find"],
    "sanitation": ["parseInt"],
    # Path traversal sinks: either modeled sinks or direct fs read calls.
    "path_traversal": [
        "pipe",
        "sink_hqbpillvul_http_write",
        "sink_hqbpillvul_fs_read",
        "fs.readFile",
        "fs.readFileSync",
    ],
}


def get_all_sign_list():
    """
    return a list of all the signature functions
    """
    res = []
    for key, value in signature_lists.items():
        res += value

    return res
