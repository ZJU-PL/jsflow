"""
Expression Builder - Constructs expression DAGs from analysis graphs.

This module provides functions to build intermediate representations (IR)
of how values flow through operations by following CONTRIBUTES_TO edges.
"""

import itertools
import logging
from typing import Dict, Iterable, List, Optional, Tuple, Union

from ..utils.utilities import wildcard
from .conditions import (
    AndCondition,
    Condition,
    NamedCondition,
    PathConstraint,
    Predicate,
    TrueCondition,
)
from .expressions import (
    Add,
    Choice,
    Concat,
    ConstNumber,
    ConstString,
    Expression,
    Sub,
    Symbol,
    UnknownOp,
)

logger = logging.getLogger(__name__)


def _node_type(G, node_id):
    return G.get_node_attr(node_id).get("type")


def _node_value(G, node_id):
    return G.get_node_attr(node_id).get("code")


def _node_taint(G, node_id):
    return bool(G.get_node_attr(node_id).get("tainted"))


def build_expressions(
    G, target_obj_ids, contains: bool = True
) -> Dict[str, Expression]:
    """
    Build expression DAGs for each target object by following CONTRIBUTES_TO edges.

    This function constructs an intermediate representation (IR) of how values flow
    through operations in the graph. It follows CONTRIBUTES_TO edges backward from
    target objects (typically sinks) to build a directed acyclic graph (DAG) of
    expressions.

    The expression DAG represents:
    - Leaf nodes: Constants (strings, numbers) or symbols (variables)
    - Internal nodes: Operations (concatenation, addition, etc.)
    - Choice nodes: Multiple possible expressions (from different execution paths)

    This IR is then encoded to Z3 constraints for solving. The DAG structure allows for efficient constraint generation and enables optimizations like common
    subexpression elimination.

    Args:
        G: Graph instance containing the analysis results.
        target_obj_ids: Iterable of target object node IDs to build expressions for.
            Typically these are sink objects that reach vulnerable functions.
        contains: Whether sink values should be modeled as "contains" (substring match)
            instead of equality. When True, allows finding inputs that produce the
            desired payload as a substring. Defaults to True.

    Returns:
        dict: Mapping from target object ID to Expression DAG. Each Expression
            represents how the value of that object is computed from source inputs.

    Example:
        >>> # Build expressions for sink objects
        >>> expressions = build_expressions(G, [sink_obj1, sink_obj2])
        >>> # Encode to Z3 and solve
        >>> for obj_id, expr in expressions.items():
        ...     solver = z3.Solver()
        ...     term = encode_to_z3(expr, solver)
        ...     solver.add(z3.Contains(term, z3.StringVal("payload")))
        ...     if solver.check() == z3.sat:
        ...         print("Exploit found:", solver.model())
    """
    memo: Dict[str, Expression] = {}

    def build(node_id: str) -> Expression:
        if node_id in memo:
            return memo[node_id]

        node_tainted = _node_taint(G, node_id)
        node_type = _node_type(G, node_id)
        node_value = _node_value(G, node_id)

        in_edges = G.get_in_edges(node_id, edge_type="CONTRIBUTES_TO")

        if not in_edges:
            expr = _leaf_expr(node_id, node_type, node_value, node_tainted)
            memo[node_id] = expr
            return expr

        grouped = _group_contributors(in_edges)
        options: List[Expression] = []
        for (op, _group), sources in grouped.items():
            # ensure deterministic ordering by index
            sources = sorted(sources, key=lambda s: s[1])
            child_exprs = [build(src) for src, _idx in sources]
            expr = _op_to_expr(op, child_exprs, node_tainted)
            options.append(expr)

        if not options:
            expr = _leaf_expr(node_id, node_type, node_value, node_tainted)
        elif len(options) == 1:
            expr = options[0]
        else:
            expr = Choice(options=options, tainted=node_tainted)

        memo[node_id] = expr
        return expr

    return {t: build(str(t)) for t in target_obj_ids}


def _leaf_expr(node_id, node_type, node_value, tainted):
    if node_type == "string" and node_value not in (None, wildcard):
        return ConstString(value=str(node_value), tainted=tainted)
    if node_type == "number" and node_value not in (None, wildcard):
        try:
            return ConstNumber(value=float(node_value), tainted=tainted)
        except (TypeError, ValueError):
            pass
    return Symbol(node_id=str(node_id), type_hint=node_type, tainted=tainted)


def _group_contributors(in_edges) -> Dict[Tuple[str, str], List[Tuple[str, int]]]:
    """
    Groups contributors by (op, group-id) and keeps operand index.
    Edge format: (src, dst, data) where data may hold 'opt' = (op, rnd, idx).
    """
    grouped: Dict[Tuple[str, str], List[Tuple[str, int]]] = {}
    for src, _dst, data in in_edges:
        opt = data.get("opt")
        if not opt:
            key = ("unknown", "none")
            idx = len(grouped.get(key, []))
        elif len(opt) < 3:
            op = opt[0] if len(opt) >= 1 and opt[0] else "unknown"
            group = opt[1] if len(opt) >= 2 and opt[1] else "none"
            key = (op, group)
            idx = len(grouped.get(key, []))
        else:
            op, group, idx = opt[0], opt[1], opt[2]
            key = (op, group)
        grouped.setdefault(key, []).append((src, int(idx)))
    return grouped


def _group_contributors_with_data(
    in_edges,
) -> Dict[Tuple[str, str], List[Tuple[str, int, Dict]]]:
    """
    Like _group_contributors but preserves edge data for guard extraction.
    """
    grouped: Dict[Tuple[str, str], List[Tuple[str, int, Dict]]] = {}
    for src, _dst, data in in_edges:
        opt = data.get("opt")
        if not opt:
            key = ("unknown", "none")
            idx = len(grouped.get(key, []))
        elif len(opt) < 3:
            op = opt[0] if len(opt) >= 1 and opt[0] else "unknown"
            group = opt[1] if len(opt) >= 2 and opt[1] else "none"
            key = (op, group)
            idx = len(grouped.get(key, []))
        else:
            op, group, idx = opt[0], opt[1], opt[2]
            key = (op, group)
        grouped.setdefault(key, []).append((src, int(idx), data))
    return grouped


def _op_to_expr(op: str, args: List[Expression], tainted: bool) -> Expression:
    op = op or "unknown"
    if op == "string_concat":
        return Concat(parts=args, tainted=tainted)
    if op == "numeric_add":
        return Add(terms=args, tainted=tainted)
    if op == "unknown_add":
        # Could be string or numeric; represent as choice
        return Choice(
            options=[
                Concat(parts=args, tainted=tainted),
                Add(terms=args, tainted=tainted),
            ],
            tainted=tainted,
        )
    if op == "sub":
        if len(args) == 2:
            return Sub(left=args[0], right=args[1], tainted=tainted)
        if args:
            # fall back to left-associative subtraction
            head, *rest = args
            return Sub(
                left=head, right=Add(terms=rest, tainted=tainted), tainted=tainted
            )
    if op == "array_join":
        return Concat(parts=args, tainted=tainted)
    return UnknownOp(op=op, args=args, tainted=tainted)


def _edge_to_condition(data: Dict) -> Condition:
    """
    Extracts a guard condition from edge data if present.
    """
    if not data:
        return TrueCondition()
    for key in ("guard", "condition", "cond", "predicate"):
        if key in data and data[key]:
            raw = data[key]
            if isinstance(raw, Condition):
                return raw
            if isinstance(raw, str):
                return NamedCondition(raw)
            if isinstance(raw, tuple) and len(raw) == 3:
                op, left, right = raw

                def _to_expr(val):
                    if isinstance(val, str):
                        return Symbol(node_id=str(val))
                    return val

                return Predicate(op=op, left=_to_expr(left), right=_to_expr(right))
    return TrueCondition()


def _combine_conditions(conds: Iterable[Condition]) -> Condition:
    parts = []
    for c in conds:
        if isinstance(c, TrueCondition):
            continue
        if isinstance(c, AndCondition):
            parts.extend(c.parts)
        else:
            parts.append(c)
    if not parts:
        return TrueCondition()
    if len(parts) == 1:
        return parts[0]
    return AndCondition(parts=parts)


def build_path_constraints(
    G,
    target_obj_ids: Iterable[str],
    *,
    path_nodes: Optional[Iterable[str]] = None,
    contains: bool = True,
    sink_value: Optional[Union[str, int, float]] = None,
) -> Dict[str, List[PathConstraint]]:
    """
    Build path-sensitive constraints for each target object.

    This performs a forward-style expansion over CONTRIBUTES_TO edges while
    preserving guards per edge. Each returned PathConstraint is a unique
    combination of operand paths and associated path conditions.
    """
    allowed_nodes = set(map(str, path_nodes)) if path_nodes else None
    memo: Dict[str, List[PathConstraint]] = {}

    def build(node_id: str) -> List[PathConstraint]:
        if node_id in memo:
            return memo[node_id]

        node_tainted = _node_taint(G, node_id)
        node_type = _node_type(G, node_id)
        node_value = _node_value(G, node_id)

        in_edges = G.get_in_edges(node_id, edge_type="CONTRIBUTES_TO")
        if allowed_nodes is not None:
            in_edges = [
                e for e in in_edges if str(e[0]) in allowed_nodes and str(e[1]) in allowed_nodes
            ]

        if not in_edges:
            expr = _leaf_expr(node_id, node_type, node_value, node_tainted)
            memo[node_id] = [PathConstraint(expr=expr, condition=TrueCondition())]
            return memo[node_id]

        grouped = _group_contributors_with_data(in_edges)
        results: List[PathConstraint] = []

        for (op, _group), sources in grouped.items():
            # ensure deterministic ordering by index
            sources = sorted(sources, key=lambda s: s[1])
            child_lists: List[List[PathConstraint]] = []
            edge_guards: List[Condition] = []
            for src, idx, data in sources:
                child_lists.append(build(src))
                edge_guards.append(_edge_to_condition(data))

            # Cartesian product over child path constraints to preserve path sensitivity
            for combo in itertools.product(*child_lists):
                child_exprs = [pc.expr for pc in combo]
                child_conditions = [pc.condition for pc in combo] + edge_guards
                expr = _op_to_expr(op, child_exprs, node_tainted)
                cond = _combine_conditions(child_conditions)
                results.append(PathConstraint(expr=expr, condition=cond))

        if not results:
            expr = _leaf_expr(node_id, node_type, node_value, node_tainted)
            results = [PathConstraint(expr=expr, condition=TrueCondition())]

        # If this is a sink and a desired value is provided, attach a contains/equality predicate
        if sink_value is not None and node_type == "string":
            extra_pred = Predicate(
                op="contains" if contains else "eq",
                left=results[0].expr,
                right=str(sink_value),
            )
            results = [
                PathConstraint(expr=pc.expr, condition=_combine_conditions([pc.condition, extra_pred]))
                for pc in results
            ]

        memo[node_id] = results
        return results

    return {t: build(str(t)) for t in target_obj_ids}
