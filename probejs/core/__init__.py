"""
Core Analysis Engine - Graph construction and symbolic execution.

This package contains the core components of probejs's analysis engine:

Modules:
--------
- graph: Graph data structure (NetworkX MultiDiGraph wrapper)
- opgen: Operation generator / symbolic execution engine
- solver: Z3 constraint solver for exploit generation
- trace_rule: Vulnerability path validation rules
- esprima: JavaScript AST parser interface

The core analysis pipeline:
---------------------------
1. Parse JavaScript source code to AST (esprima)
2. Build initial graph structure (graph)
3. Perform symbolic execution (opgen)
4. Detect vulnerability patterns (trace_rule)
5. Solve constraints for exploits (solver)
"""
