"""
Constraint Engine - Expression IR and Z3 encoding for exploit generation.

This package provides a modern constraint solving system built on an
intermediate representation (IR) of expressions and conditions. It offers
a clean separation between building expressions from graph edges, encoding
to Z3 constraints, and solving for exploit values.

Typical Usage:
--------------
    from probejs.constraints import build_expressions, encode_to_z3
    exprs = build_expressions(G, target_obj_ids)
    for target, expr in exprs.items():
        solver = z3.Solver()
        term = encode_to_z3(expr, solver)
        solver.add(z3.Contains(term, z3.StringVal("payload")))
        if solver.check() == z3.sat:
            print("Exploit:", solver.model())

The builder walks CONTRIBUTES_TO edges backward from sink objects, groups
operands using the recorded operation tuple (op, group-id, index), and
produces an expression DAG. The encoder then translates that DAG into z3 terms
with reasonable fallbacks for unknown operations.

Expression Types:
-----------------
- ConstString/ConstNumber: Literal values
- Symbol: Graph node variables (to be solved)
- Concat/Add/Sub: String/numeric operations
- Choice: Multiple possible values (from branches)
- UnknownOp: Unrecognized operations (treated as fresh variables)

Condition Types:
----------------
- Predicate: Atomic comparison (eq, contains, lt, etc.)
- AndCondition/OrCondition: Logical combinators
- NotCondition: Logical negation
- PathConstraint: Expression + path condition pair
"""

from .engine import (
    Expression,
    ConstString,
    ConstNumber,
    Symbol,
    Concat,
    Add,
    Sub,
    Choice,
    UnknownOp,
    Condition,
    TrueCondition,
    FalseCondition,
    Predicate,
    NamedCondition,
    NotCondition,
    AndCondition,
    OrCondition,
    PathConstraint,
    build_expressions,
    encode_to_z3,
    build_path_constraints,
    encode_condition,
    encode_path_constraint,
    solve_path_sensitive,
)

__all__ = [
    "Expression",
    "ConstString",
    "ConstNumber",
    "Symbol",
    "Concat",
    "Add",
    "Sub",
    "Choice",
    "UnknownOp",
    "Condition",
    "TrueCondition",
    "FalseCondition",
    "Predicate",
    "NamedCondition",
    "NotCondition",
    "AndCondition",
    "OrCondition",
    "PathConstraint",
    "build_expressions",
    "encode_to_z3",
    "build_path_constraints",
    "encode_condition",
    "encode_path_constraint",
    "solve_path_sensitive",
]
