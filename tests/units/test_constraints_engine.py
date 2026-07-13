import unittest
from unittest.mock import MagicMock, Mock
from dataclasses import dataclass

from probejs.constraints.engine import (
    Expression,
    ConstString,
    ConstNumber,
    Symbol,
    Concat,
    Add,
    Sub,
    Choice,
    UnknownOp,
    _leaf_expr,
    _group_contributors,
    _op_to_expr,
)


class TestExpressionClasses(unittest.TestCase):
    def test_expression_base(self):
        expr = Expression(tainted=True)
        self.assertTrue(expr.tainted)

    def test_const_string(self):
        expr = ConstString(value="hello", tainted=True)
        self.assertEqual(expr.value, "hello")
        self.assertTrue(expr.tainted)

    def test_const_number(self):
        expr = ConstNumber(value=42.5, tainted=False)
        self.assertEqual(expr.value, 42.5)
        self.assertFalse(expr.tainted)

    def test_symbol(self):
        expr = Symbol(node_id="node123", type_hint="string", tainted=True)
        self.assertEqual(expr.node_id, "node123")
        self.assertEqual(expr.type_hint, "string")
        self.assertTrue(expr.tainted)

    def test_concat(self):
        parts = [ConstString("a"), ConstString("b")]
        expr = Concat(parts=parts, tainted=True)
        self.assertEqual(len(expr.parts), 2)
        self.assertTrue(expr.tainted)

    def test_add(self):
        terms = [ConstNumber(1), ConstNumber(2)]
        expr = Add(terms=terms, tainted=False)
        self.assertEqual(len(expr.terms), 2)
        self.assertFalse(expr.tainted)

    def test_sub(self):
        left = ConstNumber(5)
        right = ConstNumber(3)
        expr = Sub(left=left, right=right, tainted=True)
        self.assertEqual(expr.left.value, 5)
        self.assertEqual(expr.right.value, 3)
        self.assertTrue(expr.tainted)
    
    def test_sub_default_values(self):
        expr = Sub()
        self.assertIsNone(expr.left)
        self.assertIsNone(expr.right)
        self.assertFalse(expr.tainted)

    def test_choice(self):
        options = [ConstString("opt1"), ConstString("opt2")]
        expr = Choice(options=options, tainted=False)
        self.assertEqual(len(expr.options), 2)
        self.assertFalse(expr.tainted)

    def test_unknown_op(self):
        args = [ConstString("a"), ConstString("b")]
        expr = UnknownOp(op="custom_op", args=args, tainted=True)
        self.assertEqual(expr.op, "custom_op")
        self.assertEqual(len(expr.args), 2)
        self.assertTrue(expr.tainted)


class TestLeafExpr(unittest.TestCase):
    def test_leaf_expr_string_constant(self):
        expr = _leaf_expr("node1", "string", "hello", False)
        self.assertIsInstance(expr, ConstString)
        self.assertEqual(expr.value, "hello")
        self.assertFalse(expr.tainted)

    def test_leaf_expr_number_constant(self):
        expr = _leaf_expr("node1", "number", "42", True)
        self.assertIsInstance(expr, ConstNumber)
        self.assertEqual(expr.value, 42.0)
        self.assertTrue(expr.tainted)

    def test_leaf_expr_number_float(self):
        expr = _leaf_expr("node1", "number", "3.14", False)
        self.assertIsInstance(expr, ConstNumber)
        self.assertEqual(expr.value, 3.14)

    def test_leaf_expr_invalid_number(self):
        expr = _leaf_expr("node1", "number", "not_a_number", False)
        self.assertIsInstance(expr, Symbol)
        self.assertEqual(expr.node_id, "node1")

    def test_leaf_expr_wildcard_string(self):
        from probejs.utils.utilities import wildcard
        expr = _leaf_expr("node1", "string", wildcard, False)
        self.assertIsInstance(expr, Symbol)
        self.assertEqual(expr.node_id, "node1")

    def test_leaf_expr_wildcard_number(self):
        from probejs.utils.utilities import wildcard
        expr = _leaf_expr("node1", "number", wildcard, False)
        self.assertIsInstance(expr, Symbol)
        self.assertEqual(expr.node_id, "node1")

    def test_leaf_expr_none_values(self):
        expr = _leaf_expr("node1", "string", None, False)
        self.assertIsInstance(expr, Symbol)
        self.assertEqual(expr.node_id, "node1")

    def test_leaf_expr_unknown_type(self):
        expr = _leaf_expr("node1", "object", "value", True)
        self.assertIsInstance(expr, Symbol)
        self.assertEqual(expr.node_id, "node1")
        self.assertTrue(expr.tainted)


class TestGroupContributors(unittest.TestCase):
    def test_group_contributors_empty(self):
        result = _group_contributors([])
        self.assertEqual(result, {})

    def test_group_contributors_with_opt(self):
        in_edges = [
            ("src1", "dst", {"opt": ("string_concat", "group1", 0)}),
            ("src2", "dst", {"opt": ("string_concat", "group1", 1)}),
            ("src3", "dst", {"opt": ("numeric_add", "group2", 0)}),
        ]
        result = _group_contributors(in_edges)
        self.assertEqual(len(result), 2)
        self.assertIn(("string_concat", "group1"), result)
        self.assertIn(("numeric_add", "group2"), result)

    def test_group_contributors_without_opt(self):
        in_edges = [
            ("src1", "dst", {"type": "edge"}),
            ("src2", "dst", {"type": "edge2"}),
        ]
        result = _group_contributors(in_edges)
        self.assertEqual(len(result), 1)
        self.assertIn(("unknown", "none"), result)

    def test_group_contributors_malformed_opt(self):
        in_edges = [
            ("src1", "dst", {"opt": ("op1",)}),
            ("src2", "dst", {"opt": ()}),
        ]
        result = _group_contributors(in_edges)
        self.assertEqual(len(result), 2)


class TestOpToExpr(unittest.TestCase):
    def test_op_to_expr_string_concat(self):
        args = [ConstString("a"), ConstString("b")]
        expr = _op_to_expr("string_concat", args, False)
        self.assertIsInstance(expr, Concat)
        self.assertEqual(len(expr.parts), 2)
        self.assertFalse(expr.tainted)

    def test_op_to_expr_numeric_add(self):
        args = [ConstNumber(1), ConstNumber(2)]
        expr = _op_to_expr("numeric_add", args, True)
        self.assertIsInstance(expr, Add)
        self.assertEqual(len(expr.terms), 2)
        self.assertTrue(expr.tainted)

    def test_op_to_expr_unknown_add(self):
        args = [ConstString("a"), ConstString("b")]
        expr = _op_to_expr("unknown_add", args, False)
        self.assertIsInstance(expr, Choice)
        self.assertEqual(len(expr.options), 2)

    def test_op_to_expr_sub(self):
        args = [ConstNumber(10), ConstNumber(5)]
        expr = _op_to_expr("sub", args, False)
        self.assertIsInstance(expr, Sub)
        self.assertEqual(expr.left.value, 10)
        self.assertEqual(expr.right.value, 5)

    def test_op_to_expr_sub_single_arg(self):
        args = [ConstNumber(10)]
        expr = _op_to_expr("sub", args, False)
        self.assertIsInstance(expr, Sub)

    def test_op_to_expr_sub_multiple_args(self):
        args = [ConstNumber(10), ConstNumber(3), ConstNumber(2)]
        expr = _op_to_expr("sub", args, False)
        self.assertIsInstance(expr, Sub)
        self.assertEqual(expr.left.value, 10)

    def test_op_to_expr_array_join(self):
        args = [ConstString("a"), ConstString("b")]
        expr = _op_to_expr("array_join", args, False)
        self.assertIsInstance(expr, Concat)

    def test_op_to_expr_unknown_op(self):
        args = [ConstString("x")]
        expr = _op_to_expr("custom_op", args, True)
        self.assertIsInstance(expr, UnknownOp)
        self.assertEqual(expr.op, "custom_op")
        self.assertTrue(expr.tainted)

    def test_op_to_expr_empty_op(self):
        args = [ConstString("x")]
        expr = _op_to_expr(None, args, False)
        self.assertIsInstance(expr, UnknownOp)

    def test_op_to_expr_preserves_taint(self):
        args = [ConstString("a"), ConstString("b")]
        expr = _op_to_expr("string_concat", args, True)
        self.assertTrue(expr.tainted)


if __name__ == "__main__":
    unittest.main()
