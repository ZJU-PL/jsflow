"""
Constraint engine for building and encoding expression DAGs to Z3.
"""

import logging
import itertools
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple, Union

import z3

from ..utils.utilities import wildcard

logger = logging.getLogger(__name__)


# --- Expression IR ---------------------------------------------------------


@dataclass(kw_only=True)
class Expression:
    """Base expression class."""
    tainted: bool = False


@dataclass
class ConstString(Expression):
    """Constant string expression."""
    value: str = ""


@dataclass
class ConstNumber(Expression):
    """Constant number expression."""
    value: float = 0.0


@dataclass
class Symbol(Expression):
    """Symbol expression representing a graph node."""
    node_id: str = ""
    type_hint: Optional[str] = None  # 'string' | 'number' | None


@dataclass
class Concat(Expression):
    """String concatenation expression."""
    parts: List[Expression] = field(default_factory=list)  # strings


@dataclass
class Add(Expression):
    """Numeric addition expression."""
    terms: List[Expression] = field(default_factory=list)  # numbers


@dataclass
class Sub(Expression):
    """Numeric subtraction expression."""
    left: Expression = None
    right: Expression = None


@dataclass
class Choice(Expression):
    """Choice expression representing multiple options."""
    options: List[Expression] = field(default_factory=list)


@dataclass
class UnknownOp(Expression):
    """Unknown operation expression."""
    op: str = "unknown"
    args: List[Expression] = field(default_factory=list)


# --- Path conditions ---------------------------------------------------------


@dataclass
class Condition:
    """Base class for path conditions."""


@dataclass
class TrueCondition(Condition):
    """Represents a tautology (always true)."""


@dataclass
class FalseCondition(Condition):
    """Represents a contradiction (always false)."""


@dataclass
class Predicate(Condition):
    """
    Atomic predicate over expressions or literal values.
    """
    op: str  # eq, neq, lt, le, gt, ge, contains, not_contains, prefix, suffix, regex
    left: Union[Expression, str, float, int]
    right: Union[Expression, str, float, int, None] = None


@dataclass
class NamedCondition(Condition):
    """
    A named guard when no structured predicate is available.
    """
    name: str


@dataclass
class NotCondition(Condition):
    inner: Condition


@dataclass
class AndCondition(Condition):
    parts: List[Condition] = field(default_factory=list)


@dataclass
class OrCondition(Condition):
    parts: List[Condition] = field(default_factory=list)


@dataclass
class PathConstraint:
    """
    A path-sensitive constraint: value expression + accumulated path condition.
    """
    expr: Expression
    condition: Condition = field(default_factory=TrueCondition)


# --- Builder ---------------------------------------------------------------


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

    This IR is then encoded to Z3 constraints for solving. The DAG structure allows
    for efficient constraint generation and enables optimizations like common
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


# --- Z3 encoding -----------------------------------------------------------


class _SymbolCache:
    """Cache for mixed symbols."""
    def __init__(self):
        self.cache: Dict[str, "_MixedSymbol"] = {}
        self.counter = itertools.count()

    def get(self, node_id: str, type_hint: Optional[str] = None) -> "_MixedSymbol":
        if node_id not in self.cache:
            self.cache[node_id] = _MixedSymbol(node_id, type_hint)
        return self.cache[node_id]

    def fresh(self, prefix="u") -> "_MixedSymbol":
        idx = next(self.counter)
        return _MixedSymbol(f"{prefix}{idx}", None)


class _MixedSymbol:
    """
    Holds both string and numeric views for a value. If a type_hint is given,
    only that view is created.
    """

    def __init__(self, name: str, type_hint: Optional[str] = None):
        self._number = None
        self._string = None
        if type_hint == "number":
            self._number = z3.Real(f"n{name}")
        elif type_hint == "string":
            self._string = z3.String(f"s{name}")
        else:
            self._number = z3.Real(f"n{name}")
            self._string = z3.String(f"s{name}")

    @property
    def number(self):
        return self._number

    @property
    def string(self):
        return self._string


def encode_to_z3(
    expr: Expression, solver: z3.Solver, cache: Optional[_SymbolCache] = None
):
    """
    Convert an Expression DAG to a Z3 term and add necessary constraints.

    This function recursively traverses the expression DAG and converts it to
    Z3 constraints. It handles:
    - Constants: Converted to Z3 constant values
    - Symbols: Converted to Z3 variables (with type hints)
    - Operations: Converted to Z3 operations (Concat, Sum, etc.)
    - Choices: Converted to disjunctions (OR constraints)

    The function maintains a symbol cache to ensure each graph node maps to
    a single Z3 variable, enabling efficient constraint reuse.

    Args:
        expr: The Expression DAG root to encode.
        solver: Z3 solver instance to add constraints to.
        cache: Optional symbol cache for variable reuse. If None, creates a new cache.

    Returns:
        z3.ExprRef: The primary Z3 term (string or number) representing the expression.
            The term can be used in further constraints or queries.

    Example:
        >>> solver = z3.Solver()
        >>> expr = Concat(parts=[
        ...     ConstString(value="prefix"),
        ...     Symbol(node_id="123", type_hint="string")
        ... ])
        >>> term = encode_to_z3(expr, solver)
        >>> # term represents: Concat("prefix", s123)
        >>> solver.add(z3.Contains(term, z3.StringVal("payload")))
    """
    cache = cache or _SymbolCache()
    return _encode(expr, solver, cache)[0]


def _encode(expr: Expression, solver: z3.Solver, cache: _SymbolCache):
    """
    Returns (term, kind) where kind is 'string' or 'number'.
    """
    if isinstance(expr, ConstString):
        return z3.StringVal(expr.value), "string"
    if isinstance(expr, ConstNumber):
        return z3.RealVal(expr.value), "number"
    if isinstance(expr, Symbol):
        sym = cache.get(expr.node_id, expr.type_hint)
        if expr.type_hint == "number":
            return sym.number, "number"
        if expr.type_hint == "string":
            return sym.string, "string"
        # Unknown: prefer string if available
        term = sym.string if sym.string is not None else sym.number
        return term, "string" if sym.string is not None else "number"
    if isinstance(expr, Concat):
        parts = [_require_string(_encode(p, solver, cache)) for p in expr.parts]
        if len(parts) == 1:
            return parts[0], "string"
        return z3.Concat(*parts), "string"
    if isinstance(expr, Add):
        terms = [_require_number(_encode(t, solver, cache)) for t in expr.terms]
        if len(terms) == 1:
            return terms[0], "number"
        return z3.Sum(terms), "number"
    if isinstance(expr, Sub):
        left = _require_number(_encode(expr.left, solver, cache))
        right = _require_number(_encode(expr.right, solver, cache))
        return left - right, "number"
    if isinstance(expr, Choice):
        # Create a fresh symbol and constrain it to equal one of the options
        first_term, first_kind = _encode(expr.options[0], solver, cache)
        sym = cache.fresh(prefix="choice")
        target = sym.string if first_kind == "string" else sym.number
        ors = []
        for option in expr.options:
            term, kind = _encode(option, solver, cache)
            if kind == "string" and target is not sym.string:
                # prefer string if any option is string
                target = sym.string or sym.number
            ors.append(target == term)
        solver.add(z3.Or(*ors))
        kind = "string" if target is sym.string else "number"
        return target, kind
    if isinstance(expr, UnknownOp):
        sym = cache.fresh(prefix=expr.op or "u")
        if sym.string is not None:
            return sym.string, "string"
        return sym.number, "number"

    # Fallback: treat as fresh symbol
    sym = cache.fresh(prefix="u")
    term = sym.string if sym.string is not None else sym.number
    return term, "string" if sym.string is not None else "number"


def _require_string(encoded):
    term, kind = encoded
    if kind != "string":
        # Coerce numbers to strings for concat if needed
        return z3.IntToStr(term) if isinstance(term, z3.ArithRef) else z3.StringVal("")
    return term


def _require_number(encoded):
    term, kind = encoded
    if kind != "number":
        # Coerce strings to numbers best-effort; fall back to fresh symbol
        if isinstance(term, z3.SeqRef):
            return z3.RealVal(0)
    return term


# --- Path-sensitive helpers --------------------------------------------------


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


def encode_condition(
    cond: Condition,
    solver: z3.Solver,
    cache: _SymbolCache,
) -> z3.BoolRef:
    """Encode a Condition to a Z3 BoolRef."""
    if isinstance(cond, TrueCondition):
        return z3.BoolVal(True)
    if isinstance(cond, FalseCondition):
        return z3.BoolVal(False)
    if isinstance(cond, NamedCondition):
        return z3.Bool(f"guard_{cond.name}")
    if isinstance(cond, NotCondition):
        return z3.Not(encode_condition(cond.inner, solver, cache))
    if isinstance(cond, AndCondition):
        return z3.And([encode_condition(c, solver, cache) for c in cond.parts])
    if isinstance(cond, OrCondition):
        return z3.Or([encode_condition(c, solver, cache) for c in cond.parts])
    if isinstance(cond, Predicate):
        prefer_kind = None
        if cond.op in {"lt", "le", "gt", "ge"}:
            prefer_kind = "number"
        if cond.op in {"contains", "not_contains", "prefix", "suffix", "regex"}:
            prefer_kind = "string"

        left_term, left_kind = _encode_value(cond.left, solver, cache, prefer_kind)
        right_term, right_kind = _encode_value(cond.right, solver, cache, prefer_kind)

        if cond.op in {"lt", "le", "gt", "ge"}:
            left_term = _require_number((left_term, left_kind))
            right_term = _require_number((right_term, right_kind))
        if cond.op in {"contains", "not_contains", "prefix", "suffix", "regex"}:
            left_term = _require_string((left_term, left_kind))
            right_term = _require_string((right_term, right_kind))

        op = cond.op
        if op == "eq":
            return left_term == right_term
        if op == "neq":
            return left_term != right_term
        if op == "lt":
            return left_term < right_term
        if op == "le":
            return left_term <= right_term
        if op == "gt":
            return left_term > right_term
        if op == "ge":
            return left_term >= right_term
        if op == "contains":
            return z3.Contains(left_term, right_term)
        if op == "not_contains":
            return z3.Not(z3.Contains(left_term, right_term))
        if op == "prefix":
            return z3.PrefixOf(right_term, left_term)
        if op == "suffix":
            return z3.SuffixOf(right_term, left_term)
        if op == "regex":
            return z3.InRe(left_term, z3.Re(right_term))
        # Fallback to named guard
        return z3.Bool(f"guard_{op}")
    # Unknown condition type; be permissive
    return z3.BoolVal(True)


def _encode_value(
    value, solver: z3.Solver, cache: _SymbolCache, prefer_kind: Optional[str] = None
):
    """
    Encode either an Expression or a literal into a Z3 term.
    """
    def _symbol_from_str(name: str, prefer_kind: Optional[str] = None):
        sym = cache.get(name)
        if prefer_kind == "number" and sym.number is not None:
            return sym.number, "number"
        if prefer_kind == "string" and sym.string is not None:
            return sym.string, "string"
        term = sym.string if sym.string is not None else sym.number
        return term, "string" if sym.string is not None else "number"

    if isinstance(value, Symbol):
        return _symbol_from_str(value.node_id, prefer_kind or value.type_hint)
    if isinstance(value, Expression):
        return _encode(value, solver, cache)
    if isinstance(value, (int, float)):
        return z3.RealVal(value), "number"
    if isinstance(value, str):
        # Allow guards to refer to symbols by id
        if prefer_kind in {"number", "string"}:
            return _symbol_from_str(value, prefer_kind)
        if value in cache.cache:
            return _symbol_from_str(value)
        return z3.StringVal(value), "string"
    if isinstance(value, tuple) and len(value) == 2:
        term, kind = value
        return term, kind
    # Fallback
    fresh = cache.fresh(prefix="v")
    term = fresh.string if fresh.string is not None else fresh.number
    return term, "string" if fresh.string is not None else "number"


def encode_path_constraint(
    path_constraint: PathConstraint,
    solver: z3.Solver,
    cache: Optional[_SymbolCache] = None,
) -> z3.ExprRef:
    """
    Encode a PathConstraint into Z3, returning the primary term.
    """
    cache = cache or _SymbolCache()
    term = _encode(path_constraint.expr, solver, cache)[0]
    solver.add(encode_condition(path_constraint.condition, solver, cache))
    return term


def _apply_extra_constraints(G, solver: z3.Solver, cache: _SymbolCache):
    """
    Apply extra constraints captured during analysis (sanitizers, etc.).
    """
    for targets, rule, literal in getattr(G, "extra_constraints", []):
        for target in targets:
            sym = cache.get(str(target))
            if isinstance(literal, str):
                term = sym.string or sym.number
                if term is None:
                    continue
                if rule == "not-contains":
                    solver.add(z3.Not(z3.Contains(term, z3.StringVal(literal))))
                elif rule == "contains":
                    solver.add(z3.Contains(term, z3.StringVal(literal)))


def solve_path_sensitive(
    G,
    final_objs: Iterable[str],
    initial_objs: Optional[Iterable[str]] = None,
    contains: bool = True,
    path_nodes: Optional[Iterable[str]] = None,
):
    """
    Path-sensitive solver built on top of the expression/condition IR.

    Yields:
        (assertions, results) per path. `results` is \"failed\" on UNSAT or a
        dict of variable -> (name, value) on SAT.
    """
    sink_value = getattr(G, "solve_from", None)
    constraints = build_path_constraints(
        G,
        final_objs,
        path_nodes=path_nodes,
        contains=contains,
        sink_value=sink_value,
    )

    for final_obj, path_constraints in constraints.items():
        for pc in path_constraints:
            solver = z3.Solver()
            cache = _SymbolCache()
            term = encode_path_constraint(pc, solver, cache)

            # Default safety constraints similar to legacy solver
            if isinstance(term, z3.SeqRef):
                solver.add(z3.Not(z3.PrefixOf(z3.StringVal(";"), term)))
                solver.add(z3.Not(z3.PrefixOf(z3.StringVal("&"), term)))

            _apply_extra_constraints(G, solver, cache)
            solver.set(timeout=2000)

            try:
                if solver.check() == z3.unsat:
                    yield solver.assertions(), "failed"
                    continue
                model = solver.model()
            except z3.Z3Exception:
                yield solver.assertions(), "failed"
                continue

            path_results = {}
            for var in model:
                vn = str(var)
                if initial_objs and vn[1:] not in initial_objs:
                    continue
                if getattr(G, "reverse_names", None) and G.reverse_names[vn[1:]]:
                    name = ", ".join(G.reverse_names[vn[1:]])
                    path_results[vn] = (name, model[var])
            yield solver.assertions(), (path_results or model)
