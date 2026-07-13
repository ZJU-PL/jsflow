# Architecture

## Overview

The probejs module consists of several key components:

## Core Modules

- **`graph.py`**: Implements the `Graph` class, which maintains a NetworkX-based multi-digraph representing the code structure, data flows, and control flows
- **`opgen.py`**: Operation generator that performs AST traversal and static analysis
- **`launcher.py`**: Main entry point and command-line interface
- **`vul_checking.py`**: Vulnerability detection engine that applies trace rules to identify security issues
- **`trace_rule.py`**: Defines trace rules for vulnerability pattern matching
- **`solver.py`**: Constraint solver using Z3 for path feasibility analysis and exploit generation. Implements `solve2()` which builds constraint systems from graph operations (string concatenation, numeric addition) and solves them to determine if vulnerable paths are reachable
- **`modeled_js_builtins.py`**: Models JavaScript built-in functions and objects
- **`modeled_builtin_modules.py`**: Models Node.js built-in modules (fs, child_process, etc.)

## Supporting Modules

- **`logger.py`**: Logging utilities with file and console output support
- **`helpers.py`**: Utility functions for JavaScript value handling
- **`utilities.py`**: Data structures and utilities for branch tracking
- **`esprima.py`**: JavaScript parser interface
- **`vul_func_lists.py`**: Lists of vulnerable function signatures

## How It Works

### Analysis Pipeline

1. **Parsing**: JavaScript source code is parsed into an Abstract Syntax Tree (AST) using Esprima
   - The AST is converted to CSV format for processing
   - Each node is assigned a unique identifier

2. **Graph Construction**: The AST is converted into a NetworkX MultiDiGraph structure with nodes representing:
   - AST nodes (statements, expressions, functions)
   - Objects and their properties
   - Scopes and variables
   - JavaScript built-in prototypes and constructors

3. **Static Analysis**: The tool simulates program execution, tracking:
   - Object property accesses and modifications
   - Function calls and returns
   - Control flow paths (branches, loops, conditionals)
   - Data flow from sources (user input) to sinks (vulnerable functions)
   - String concatenations and numeric operations

4. **Graph Edge Types**: The graph uses several edge types to represent relationships:
   - `REACHES`: Data flow relationships between variables
   - `POINTS_TO`: Object reference relationships
   - `FLOWS_TO`: Control flow between statements
   - `CONTRIBUTES_TO`: How values contribute to expressions (with operation tags)
   - `CALLS`: Function call relationships
   - `ENTRY`/`EXIT`: Function entry and exit points
   - `PROPERTY`: Object property access relationships

5. **Vulnerability Detection**: Trace rules are applied to identify paths from user input (sources) to vulnerable sinks:
   - Sources are identified (e.g., `req.query`, `req.body`, `req.params`)
   - Sinks are identified based on vulnerability type (e.g., `child_process.exec()` for OS command injection)
   - Path analysis finds all possible data flow paths from sources to sinks

6. **Constraint Solving**: For each vulnerable path, the solver:
   - Builds a Z3 constraint system representing the operations along the path
   - Models string concatenations and numeric additions as constraints
   - Checks path feasibility (whether the path can be executed)
   - Generates concrete input values that would trigger the vulnerability (if `-X` flag is used)

7. **Path Reporting**: Vulnerable paths are reported with:
   - Line numbers and code snippets
   - Source and sink locations
   - Constraint system (if solving succeeded)
   - Exploit payloads (if auto-exploit is enabled)

## Output Format

Analysis results are saved in timestamped directories under `logs/` (e.g., `logs/20240101_120000/`):

### Log Files

- **`run_log.log`**: Main execution log containing:
  - Analysis progress and status
  - Detected vulnerabilities with paths
  - Error messages and warnings
  - Execution statistics

- **`graph_log.log`**: Graph construction details including:
  - Node and edge creation events
  - Scope and variable tracking
  - Function call information

### Graph Exports

- **`opg_nodes.tsv`**: Object property graph nodes in TSV format with columns:
  - Node ID
  - Node type (AST node, object, property, etc.)
  - Code snippet
  - Line number
  - File path

- **`opg_rels.tsv`**: Object property graph relationships in TSV format with columns:
  - Source node ID
  - Target node ID
  - Edge type (REACHES, POINTS_TO, etc.)
  - Edge attributes (operation tags, etc.)

### Vulnerability Reports

- **`proto_pollution.log`**: Prototype pollution findings (if detected) with:
  - Location of prototype modification
  - Affected prototype chain
  - Code context

- **`int_prop_tampering.log`**: Internal property tampering findings (if detected) with:
  - Write locations (where properties are modified)
  - Use locations (where properties are accessed)
  - Property names

- **`vul_func_names.csv`**: Detected vulnerable functions with:
  - Function name
  - File path
  - Line number
  - Vulnerability type


