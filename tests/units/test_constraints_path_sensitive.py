import unittest
from collections import defaultdict

import z3

from probejs.constraints import (
    Add,
    AndCondition,
    ConstString,
    NamedCondition,
    PathConstraint,
    Predicate,
    TrueCondition,
    build_path_constraints,
    encode_condition,
    encode_path_constraint,
    solve_path_sensitive,
)


class FakeGraph:
    def __init__(self, node_attrs, edges, extra_constraints=None):
        self.node_attrs = node_attrs
        self.edges = edges
        self.extra_constraints = extra_constraints or []
        self.reverse_names = defaultdict(list)
        self.solve_from = None

    def get_node_attr(self, node_id):
        return self.node_attrs.get(node_id, {})

    def get_in_edges(self, node_id, edge_type=None):
        if edge_type and edge_type != "CONTRIBUTES_TO":
            return []
        return [e for e in self.edges if str(e[1]) == str(node_id)]


class TestPathConditions(unittest.TestCase):
    def test_encode_condition_predicate(self):
        solver = z3.Solver()
        pred = Predicate(op="contains", left="abc", right="b")
        from probejs.constraints.engine import _SymbolCache

        cond = encode_condition(pred, solver, _SymbolCache())
        solver.add(cond)
        self.assertEqual(solver.check(), z3.sat)

    def test_named_condition(self):
        solver = z3.Solver()
        named = NamedCondition("g1")
        from probejs.constraints.engine import _SymbolCache

        cond = encode_condition(named, solver, _SymbolCache())
        solver.add(cond)
        # guard defaults to an unconstrained Bool, so both sat/unsat are acceptable.
        self.assertIn(solver.check(), (z3.sat, z3.unknown))


class TestPathBuilder(unittest.TestCase):
    def setUp(self):
        node_attrs = {
            "a": {"type": "string", "code": "foo", "tainted": False},
            "b": {"type": "string", "code": "bar", "tainted": False},
            "c": {"type": "string", "code": None, "tainted": False},
        }
        edges = [
            ("a", "c", {"opt": ("string_concat", "g", 0), "guard": ("eq", "a", "a")}),
            ("b", "c", {"opt": ("string_concat", "g", 1)}),
        ]
        self.graph = FakeGraph(node_attrs, edges)

    def test_build_path_constraints_concat(self):
        pcs = build_path_constraints(self.graph, ["c"])
        self.assertEqual(len(pcs["c"]), 1)
        pc = pcs["c"][0]
        self.assertTrue(
            isinstance(pc.condition, AndCondition) or isinstance(pc.condition, Predicate)
        )

    def test_encode_path_constraint(self):
        pcs = build_path_constraints(self.graph, ["c"])
        solver = z3.Solver()
        term = encode_path_constraint(pcs["c"][0], solver)
        solver.add(z3.Contains(term, z3.StringVal("foo")))
        self.assertEqual(solver.check(), z3.sat)

    def test_solve_path_sensitive_contains(self):
        self.graph.solve_from = "foo"
        results = list(
            solve_path_sensitive(
                self.graph,
                final_objs=["c"],
                contains=True,
            )
        )
        self.assertTrue(results)
        # At least one result should be satisfiable (not "failed")
        self.assertTrue(any(r[1] != "failed" for r in results))


class TestPathConditionWithNumbers(unittest.TestCase):
    def test_numeric_addition_condition(self):
        node_attrs = {
            "x": {"type": "number", "code": 1, "tainted": False},
            "y": {"type": "number", "code": 2, "tainted": False},
            "z": {"type": "number", "code": None, "tainted": False},
        }
        edges = [
            ("x", "z", {"opt": ("numeric_add", "g", 0)}),
            ("y", "z", {"opt": ("numeric_add", "g", 1), "guard": ("gt", "y", 0)}),
        ]
        g = FakeGraph(node_attrs, edges)
        pcs = build_path_constraints(g, ["z"])
        solver = z3.Solver()
        term = encode_path_constraint(pcs["z"][0], solver)
        solver.add(term == 3)
        self.assertEqual(solver.check(), z3.sat)


class TestPathConstraintDataclass(unittest.TestCase):
    def test_path_constraint_defaults(self):
        pc = PathConstraint(expr=Add(terms=[]))
        self.assertIsInstance(pc.condition, TrueCondition)


if __name__ == "__main__":
    unittest.main()
