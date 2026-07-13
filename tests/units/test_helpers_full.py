import unittest
from unittest.mock import MagicMock, Mock
import math
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from probejs.utils.helpers import (
    eval_value, val_to_str, val_to_float, cmp, js_cmp, is_int,
    is_wildcard_obj, get_func_name, to_python_array
)
from probejs.utils.utilities import NodeHandleResult, wildcard, undefined, BranchTag


class TestValToStr(unittest.TestCase):
    def test_float_value(self):
        result = val_to_str(3.14159)
        self.assertEqual(result, "3.14159")

    def test_int_value(self):
        result = val_to_str(42)
        self.assertEqual(result, "42")

    def test_none_value(self):
        result = val_to_str(None)
        self.assertEqual(result, wildcard)

    def test_wildcard_value(self):
        result = val_to_str(wildcard)
        self.assertEqual(result, wildcard)

    def test_string_value(self):
        result = val_to_str("hello")
        self.assertEqual(result, "hello")

    def test_custom_default(self):
        result = val_to_str(None, default="custom")
        self.assertEqual(result, "custom")


class TestValToFloat(unittest.TestCase):
    def test_float_value(self):
        result = val_to_float(3.14)
        self.assertEqual(result, 3.14)

    def test_int_value(self):
        result = val_to_float(42)
        self.assertEqual(result, 42.0)

    def test_none_value(self):
        result = val_to_float(None)
        self.assertEqual(result, wildcard)

    def test_wildcard_value(self):
        result = val_to_float(wildcard)
        self.assertEqual(result, wildcard)

    def test_undefined_value(self):
        result = val_to_float(undefined)
        self.assertEqual(result, wildcard)

    def test_invalid_string(self):
        result = val_to_float("not_a_number")
        self.assertTrue(math.isnan(result))


class TestCmp(unittest.TestCase):
    def test_greater(self):
        self.assertEqual(cmp(5, 3), 1)

    def test_less(self):
        self.assertEqual(cmp(3, 5), -1)

    def test_equal(self):
        self.assertEqual(cmp(5, 5), 0)


class TestJsCmp(unittest.TestCase):
    def test_same_type_greater(self):
        self.assertEqual(js_cmp(5, 3), 1)

    def test_same_type_less(self):
        self.assertEqual(js_cmp(3, 5), -1)

    def test_same_type_equal(self):
        self.assertEqual(js_cmp(5, 5), 0)

    def test_undefined_both(self):
        self.assertEqual(js_cmp(undefined, undefined), 0)

    def test_number_and_string(self):
        result = js_cmp(5, "10")
        self.assertEqual(result, -1)


class TestIsInt(unittest.TestCase):
    def test_int_value(self):
        self.assertTrue(is_int(42))

    def test_float_value(self):
        self.assertTrue(is_int(42.0))

    def test_string_int(self):
        self.assertTrue(is_int("42"))

    def test_string_float(self):
        # "42.0" cannot be directly converted to int
        self.assertFalse(is_int("42.0"))

    def test_invalid_string(self):
        self.assertFalse(is_int("abc"))

    def test_none_value(self):
        self.assertFalse(is_int(None))

    def test_wildcard(self):
        self.assertFalse(is_int(wildcard))


class TestEvalValue(unittest.TestCase):
    def test_eval_true(self):
        G = MagicMock()
        G.true_obj = 1
        evaluated, js_type = eval_value(G, "true")
        self.assertEqual(evaluated, True)
        self.assertEqual(js_type, "boolean")

    def test_eval_false(self):
        G = MagicMock()
        G.false_obj = 2
        evaluated, js_type = eval_value(G, "false")
        self.assertEqual(evaluated, False)
        self.assertEqual(js_type, "boolean")

    def test_eval_nan(self):
        G = MagicMock()
        G.false_obj = 3
        evaluated, js_type = eval_value(G, "NaN")
        self.assertTrue(math.isnan(evaluated))
        self.assertEqual(js_type, "number")

    def test_eval_infinity(self):
        G = MagicMock()
        G.infinity_obj = 4
        evaluated, js_type = eval_value(G, "Infinity")
        self.assertEqual(evaluated, math.inf)
        self.assertEqual(js_type, "number")

    def test_eval_negative_infinity(self):
        G = MagicMock()
        G.negative_infinity_obj = 5
        evaluated, js_type = eval_value(G, "-Infinity")
        self.assertEqual(evaluated, -math.inf)
        self.assertEqual(js_type, "number")

    def test_eval_number(self):
        G = MagicMock()
        evaluated, js_type = eval_value(G, "42")
        self.assertEqual(evaluated, 42)
        self.assertEqual(js_type, "number")

    def test_eval_float(self):
        G = MagicMock()
        evaluated, js_type = eval_value(G, "3.14")
        self.assertAlmostEqual(evaluated, 3.14)
        self.assertEqual(js_type, "number")

    def test_eval_string(self):
        G = MagicMock()
        evaluated, js_type = eval_value(G, "'hello'")
        self.assertEqual(evaluated, "hello")
        self.assertEqual(js_type, "string")

    def test_eval_with_return_obj_node(self):
        G = MagicMock()
        G.add_obj_node.return_value = 100
        evaluated, js_type, result = eval_value(G, "42", return_obj_node=True)
        self.assertEqual(evaluated, 42)
        self.assertEqual(js_type, "number")
        self.assertEqual(result.obj_nodes, [100])


class TestIsWildcardObj(unittest.TestCase):
    def test_wildcard_object(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "object", "code": wildcard}
        self.assertTrue(is_wildcard_obj(G, 1))

    def test_wildcard_array(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "array", "code": wildcard}
        self.assertTrue(is_wildcard_obj(G, 1))

    def test_wildcard_number(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "number", "code": wildcard}
        self.assertTrue(is_wildcard_obj(G, 1))

    def test_wildcard_string(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "string", "code": wildcard}
        self.assertTrue(is_wildcard_obj(G, 1))

    def test_wildcard_type(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": wildcard, "code": "something"}
        self.assertTrue(is_wildcard_obj(G, 1))

    def test_non_wildcard(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "string", "code": "hello"}
        self.assertFalse(is_wildcard_obj(G, 1))


class TestGetFuncName(unittest.TestCase):
    def test_function_decl(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_FUNC_DECL"}
        G.get_name_from_child.return_value = "myFunc"
        result = get_func_name(G, 1)
        self.assertEqual(result, "myFunc")

    def test_closure(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_CLOSURE"}
        G.get_name_from_child.return_value = "closureFunc"
        result = get_func_name(G, 1)
        self.assertEqual(result, "closureFunc")

    def test_function_decl(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_FUNC_DECL"}
        G.get_name_from_child.return_value = "myFunc"
        result = get_func_name(G, 1)
        self.assertEqual(result, "myFunc")

    def test_closure(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_CLOSURE"}
        G.get_name_from_child.return_value = "closureFunc"
        result = get_func_name(G, 1)
        self.assertEqual(result, "closureFunc")

    def test_method_call(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_METHOD_CALL"}
        G.get_ordered_ast_child_nodes.return_value = [1, 2]
        G.get_node_attr.side_effect = lambda n: {"type": "AST_NAME"} if n == 2 else {}
        G.get_name_from_child.return_value = "methodName"
        result = get_func_name(G, 1)
        self.assertEqual(result, "methodName")

    def test_ast_call(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_CALL"}
        G.get_ordered_ast_child_nodes.return_value = [1, 2]
        G.get_node_attr.side_effect = lambda n: {"type": "AST_NAME"} if n == 1 else {}
        G.get_name_from_child.return_value = "funcName"
        result = get_func_name(G, 1)
        self.assertEqual(result, "funcName")

    def test_ast_new(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_NEW"}
        G.get_ordered_ast_child_nodes.return_value = [1, 2]
        G.get_node_attr.side_effect = lambda n: {"type": "AST_NAME"} if n == 1 else {}
        G.get_name_from_child.return_value = "Constructor"
        result = get_func_name(G, 1)
        self.assertEqual(result, "Constructor")

    def test_ast_assign_function(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_ASSIGN"}
        G.get_ordered_ast_child_nodes.return_value = [1, 2]
        G.get_node_attr.side_effect = lambda n: {"type": "AST_FUNC_DECL"} if n == 2 else {"type": "AST_NAME"}
        G.get_name_from_child.return_value = "assignedFunc"
        result = get_func_name(G, 1)
        self.assertEqual(result, "assignedFunc")

    def test_other_node_type(self):
        G = MagicMock()
        G.get_node_attr.return_value = {"type": "AST_EXPR"}
        G.get_name_from_child.return_value = "someName"
        result = get_func_name(G, 1)
        self.assertEqual(result, "someName")


class TestToPythonArray(unittest.TestCase):
    def test_empty_array(self):
        G = MagicMock()
        G.get_prop_name_nodes.return_value = []
        elements, edge_data = to_python_array(G, 1)
        self.assertEqual(elements, [[]])
        self.assertEqual(edge_data, [[]])


if __name__ == "__main__":
    unittest.main()
