"""
probejs: A Static Analysis Framework for JavaScript Vulnerability Detection

probejs is a static analysis tool that performs symbolic execution on JavaScript
code to detect security vulnerabilities. It generates Object Property Graphs (OPG)
from JavaScript source code and analyzes data flows to identify potential security
issues.

Key Features:
    - Object Property Graph generation from JavaScript AST
    - Symbolic execution with path tracking
    - Vulnerability detection (OS command injection, XSS, prototype pollution, etc.)
    - Support for npm module analysis
    - Export to CSV/TSV for further analysis

Main Components:
    - Graph: Core graph data structure for representing code
    - opgen: Operation generator for AST traversal and symbolic execution
    - vul_checking: Vulnerability detection engine
    - trace_rule: Pattern matching rules for vulnerability detection
    - solver: Constraint solver for path analysis

Usage:
    Command line:
        python -m probejs input.js -t os_command

    Programmatic:
        from probejs.launcher import unittest_main
        result, graph = unittest_main('input.js', vul_type='os_command')

Example:
    >>> from probejs.launcher import unittest_main
    >>> result, graph = unittest_main('test.js', vul_type='xss')
    >>> print(f"Vulnerabilities found: {len(result)}")
"""

__version__ = "1.0.0"

# Import submodules to maintain backward compatibility and API structure
from .core import graph
from .core import opgen
from .core import trace_rule
from .core import solver
from .utils import logger
from .utils import helpers
from .utils import utilities
from .vuln import vul_checking
from . import launcher

# Expose commonly used classes directly
from .core.graph import Graph

__all__ = [
    "Graph",
    "launcher",
    "opgen",
    "vul_checking",
    "trace_rule",
    "solver",
    "logger",
    "helpers",
    "utilities",
]
