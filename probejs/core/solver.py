"""
Constraint solving helpers built on top of z3.

This module reconstructs symbolic constraints from the CONTRIBUTES_TO edges in
the analysis graph to reason about possible concrete values at sinks. It is
invoked by vulnerability checks to see whether an attack payload can satisfy
the derived equations (strings, numbers, or mixed types).
"""

from . import opgen
from .graph import Graph
from ..utils.utilities import wildcard
from collections import defaultdict
from functools import reduce
from operator import add
import sty
import re
import z3
import time


class MixedSymbol:
    """Thin wrapper that holds both string and numeric z3 symbols for a node."""

    def __init__(self, name, _type=None):
        super().__init__()
        self._number = None
        self._string = None
        if _type == "number":
            self._number = z3.Real(f"n{name}")
        elif _type == "string":
            self._string = z3.String(f"s{name}")
        else:
            self._number = z3.Real(f"n{name}")
            self._string = z3.String(f"s{name}")

    def number(self):
        return self._number

    def string(self):
        return self._string


def check_number_operation(arr):
    for i in arr:
        if type(i) is not MixedSymbol:
            return False
        elif i.number() is None:
            return False
    return True


def check_string_operation(arr):
    for i in arr:
        if type(i) is not MixedSymbol:
            return False
        elif i.string() is None:
            return False
    return True


def solve2(G: Graph, final_objs, initial_objs=None, contains=True):
    time1 = time.time()
    print(
        "final objs:", final_objs, "value:", G.solve_from, "initial objs:", initial_objs
    )

    from probejs.constraints.engine import solve_path_sensitive, collect_ast_guards

    # Collect AST-level if-guards from the enclosing call site.
    call_ast = getattr(G, "_call_ast_node_id", None)
    extra_conditions = collect_ast_guards(G, call_ast) if call_ast is not None else None

    engine = solve_path_sensitive(
        G,
        final_objs,
        initial_objs=initial_objs,
        contains=contains,
        extra_conditions=extra_conditions,
    )

    for assertions, results in engine:
        yield (assertions, results)

    G.solver_time += time.time() - time1


def solve1(G: Graph, final_objs, initial_objs=None, contains=True):
    results = []

    def get_symbol(obj):
        nonlocal G, symbol, solver
        if obj not in symbol:
            t = G.get_node_attr(obj).get("type")
            v = G.get_node_attr(obj).get("code")
            # print('type =', t, 'value =', v)
            if t == "number":
                symbol[obj] = z3.Real(f"n{obj}")
                solver.add(symbol[obj] == float(v))
            elif t == "string":
                symbol[obj] = z3.String(f"s{obj}")
                if obj in final_objs and contains:
                    solver.add(z3.Contains(symbol[obj], v))  # str contains
                    # solver.add(z3.InRe(symbol[obj], z3.Re(v))) # regex
                else:
                    solver.add(symbol[obj] == z3.StringVal(v))
            # elif v == wildcard or t == 'object':
            else:
                symbol[obj] = (z3.Real(f"n{obj}"), z3.String(f"s{obj}"))

    for final_obj in final_objs:
        original_type = G.get_node_attr(final_obj).get("type")
        original_value = G.get_node_attr(final_obj).get("code")
        if type(G.solve_from) in [int, float]:
            G.set_node_attr(final_obj, ("type", "number"))
        elif type(G.solve_from) == str:
            G.set_node_attr(final_obj, ("type", "string"))
        G.set_node_attr(final_obj, ("code", G.solve_from))
        symbol = {}
        solver = z3.Solver()

        q = [final_obj]
        get_symbol(final_obj)
        # visited_objs = set()
        while q:
            obj = q.pop(0)
            contributors = []
            in_edges = G.get_in_edges(obj, edge_type="CONTRIBUTES_TO")
            print(in_edges)
            for e in in_edges:
                op = e[-1].get("op", "")
                contributors.append((op, e[0]))
                if e[0] not in q:
                    q.append(e[0])
            contributors = sorted(contributors)
            for tag1, source1 in contributors:
                match = re.match(r"(\w+)#(\w+)", tag1)
                if not match:
                    continue
                op, order = match.groups()
                if order != "0":
                    continue
                get_symbol(source1)
                for tag2, source2 in contributors:
                    get_symbol(source2)
                    if tag2 == f"{op}#1":
                        if type(symbol[source1]) == tuple:
                            if type(symbol[source2]) == tuple:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2][0]
                                            == symbol[obj][0]
                                        )
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2][1]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2][0]
                                            == symbol[obj]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2][1]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.ArithRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2]
                                            == symbol[obj][0]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][0] + symbol[source2]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.SeqRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1][1] + symbol[source2]
                                            == symbol[obj]
                                        )
                        elif type(symbol[source1]) == z3.ArithRef:
                            if type(symbol[source2]) == tuple:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][0]
                                            == symbol[obj][0]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][0]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.ArithRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj][0]
                                        )
                                elif type(symbol[obj]) == z3.ArithRef:
                                    if tag1.startswith(
                                        "numeric_add"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj]
                                        )
                        elif type(symbol[source1]) == z3.SeqRef:
                            if type(symbol[source2]) == tuple:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][1]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2][1]
                                            == symbol[obj]
                                        )
                            elif type(symbol[source2]) == z3.SeqRef:
                                if type(symbol[obj]) == tuple:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj][1]
                                        )
                                elif type(symbol[obj]) == z3.SeqRef:
                                    if tag1.startswith(
                                        "string_concat"
                                    ) or tag1.startswith("unknown_add"):
                                        solver.add(
                                            symbol[source1] + symbol[source2]
                                            == symbol[obj]
                                        )
                        break
        for targets, rule, literal in G.extra_constraints:
            for target in targets:
                if type(literal) == str:
                    get_symbol(target)
                    if type(symbol[target]) == tuple:
                        if rule == "not-contains":
                            solver.add(
                                z3.Not(
                                    z3.Contains(
                                        symbol[target][1], z3.StringVal(literal)
                                    )
                                )
                            )
                        elif rule == "contains":
                            solver.add(
                                z3.Contains(symbol[target][1], z3.StringVal(literal))
                            )
                        # elif rule == 'contains':
                    elif type(symbol[target]) == z3.SeqRef:
                        if rule == "not-contains":
                            solver.add(
                                z3.Not(
                                    z3.Contains(symbol[target], z3.StringVal(literal))
                                )
                            )
                        elif rule == "contains":
                            solver.add(
                                z3.Contains(symbol[target], z3.StringVal(literal))
                            )
        G.set_node_attr(final_obj, ("type", original_type))
        G.set_node_attr(final_obj, ("code", original_value))
        solver.set(timeout=30000)
        path_results = defaultdict(list)
        try:
            if solver.check() == z3.unsat:
                # print(solver.assertions())
                yield (solver.assertions(), "failed")
                continue
            model = solver.model()
        except z3.Z3Exception:
            yield (solver.assertions(), "failed")
            continue
        for var in model:
            vn = str(var)
            if initial_objs and vn[1:] not in initial_objs:
                continue
            # if vn[1:] in G.reverse_names:
            if G.reverse_names[vn[1:]]:
                name = ", ".join(G.reverse_names[vn[1:]]) + f"({vn})"
                path_results[name].append(model[var])
            else:
                # results[vn] = model[var]
                pass
        # results.append(solver.assertions(), path_results)
        yield (solver.assertions(), path_results or "timeout")
    # return results


solve = solve2
