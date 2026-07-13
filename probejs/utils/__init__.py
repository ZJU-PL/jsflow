"""
Utility Modules - Helper classes and functions for probejs.

This package provides shared utilities used across the probejs analysis engine.

Modules:
--------
- utilities: Core data structures (NodeHandleResult, BranchTag, etc.)
- helpers: Value conversion and object graph manipulation helpers
- helpers2: Additional helper functions
- logger: Logging utilities for analysis output

Key Classes:
------------
- NodeHandleResult: Return type for AST node handlers
- BranchTag: Branch tracking for path-sensitive analysis
- DictCounter: Counter with default value support
- _SpecialValue: Sentinel values (wildcard, undefined)

Key Functions:
--------------
- eval_value: Evaluate JavaScript literals to Python values
- val_to_str/val_to_float: Value conversion utilities
- copy_objs_for_branch: Branch-aware object copying
"""
