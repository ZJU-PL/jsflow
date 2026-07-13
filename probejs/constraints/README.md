# Constraint Collection

This package provides a modern, path-sensitive constraint builder on top of
probejs's graph. It complements (does not replace) the legacy solver in
`probejs/core/solver.py`.

## APIs

- `build_expressions`: Legacy-compatible expression DAG builder
- `encode_to_z3`: Encode expression DAG to Z3
- `build_path_constraints`: Path-sensitive builder returning `(expr, path_condition)` pairs
- `encode_path_constraint`: Encode both value and guard to Z3
- `solve_path_sensitive`: Convenience wrapper that solves per-path and yields models

## Path Conditions

Path conditions capture branch predicates, sanitization guards, and any edge
guards recorded on `CONTRIBUTES_TO` edges. They are preserved per-branch (no
collapse), enabling path-sensitive reasoning.

## Usage

```python
from probejs.constraints import solve_path_sensitive

G.solve_from = "; rm -rf /"
for assertions, results in solve_path_sensitive(G, final_objs=[sink_obj]):
    if results != "failed":
        print("Exploit found", results)
```

You can optionally pass `path_nodes` to restrict solving to a specific
source→sink path discovered by the analyzer.