import math
import unittest
from unittest.mock import MagicMock, patch

from probejs.utils import helpers
from probejs.utils.utilities import wildcard, undefined, NodeHandleResult, BranchTag


class TestHelpersAdvanced(unittest.TestCase):
    def test_eval_value_boolean_literals(self):
        G = MagicMock()
        G.true_obj = 1
        G.false_obj = 2
        
        evaluated, js_type = helpers.eval_value(G, "true")
        self.assertTrue(evaluated)
        self.assertEqual(js_type, "boolean")
        
        evaluated, js_type = helpers.eval_value(G, "false")
        self.assertFalse(evaluated)
        self.assertEqual(js_type, "boolean")

    def test_eval_value_special_numbers(self):
        G = MagicMock()
        G.false_obj = 2
        G.infinity_obj = 3
        G.negative_infinity_obj = 4
        
        evaluated, js_type = helpers.eval_value(G, "NaN")
        self.assertTrue(math.isnan(evaluated))
        self.assertEqual(js_type, "number")
        
        evaluated, js_type = helpers.eval_value(G, "Infinity")
        self.assertEqual(evaluated, math.inf)
        self.assertEqual(js_type, "number")
        
        evaluated, js_type = helpers.eval_value(G, "-Infinity")
        self.assertEqual(evaluated, -math.inf)
        self.assertEqual(js_type, "number")

    def test_eval_value_string_and_number(self):
        G = MagicMock()
        
        evaluated, js_type = helpers.eval_value(G, "'hello'")
        self.assertEqual(evaluated, "hello")
        self.assertEqual(js_type, "string")
        
        evaluated, js_type = helpers.eval_value(G, "42")
        self.assertEqual(evaluated, 42)
        self.assertEqual(js_type, "number")
        
        evaluated, js_type = helpers.eval_value(G, "3.14")
        self.assertEqual(evaluated, 3.14)
        self.assertEqual(js_type, "number")

    def test_eval_value_with_object_node(self):
        G = MagicMock()
        G.add_obj_node.return_value = 100
        
        evaluated, js_type, result = helpers.eval_value(
            G, "'test'", return_obj_node=True, ast_node=50
        )
        self.assertEqual(evaluated, "test")
        self.assertEqual(js_type, "string")
        self.assertEqual(result.obj_nodes, [100])

    def test_cmp_function(self):
        self.assertEqual(helpers.cmp(1, 2), -1)
        self.assertEqual(helpers.cmp(2, 1), 1)
        self.assertEqual(helpers.cmp(1, 1), 0)
        self.assertEqual(helpers.cmp("a", "b"), -1)

    def test_js_cmp_same_types(self):
        self.assertEqual(helpers.js_cmp(1, 2), -1)
        self.assertEqual(helpers.js_cmp(2, 1), 1)
        self.assertEqual(helpers.js_cmp(1, 1), 0)
        self.assertEqual(helpers.js_cmp("a", "b"), -1)
        self.assertEqual(helpers.js_cmp("b", "a"), 1)
        self.assertEqual(helpers.js_cmp("a", "a"), 0)
        self.assertEqual(helpers.js_cmp(undefined, undefined), 0)

    def test_js_cmp_different_types_numeric_conversion(self):
        self.assertEqual(helpers.js_cmp("2", 10), -1)
        self.assertEqual(helpers.js_cmp("10", 2), 1)
        self.assertEqual(helpers.js_cmp(10, "2"), 1)

    def test_val_to_str_numbers(self):
        self.assertEqual(helpers.val_to_str(3.14159), "3.14159")
        self.assertEqual(helpers.val_to_str(42), "42")
        self.assertEqual(helpers.val_to_str(0.0001), "0.0001")

    def test_val_to_str_none_and_wildcard(self):
        self.assertIs(helpers.val_to_str(None), wildcard)
        self.assertIs(helpers.val_to_str(wildcard), wildcard)
        self.assertEqual(helpers.val_to_str(None, default="N/A"), "N/A")

    def test_val_to_float_valid_inputs(self):
        self.assertEqual(helpers.val_to_float("3.14"), 3.14)
        self.assertEqual(helpers.val_to_float("42"), 42.0)
        self.assertEqual(helpers.val_to_float(10), 10.0)
        self.assertEqual(helpers.val_to_float(3.5), 3.5)

    def test_val_to_float_special_inputs(self):
        self.assertIs(helpers.val_to_float(None), wildcard)
        self.assertIs(helpers.val_to_float(wildcard), wildcard)
        self.assertIs(helpers.val_to_float(undefined), wildcard)
        self.assertTrue(math.isnan(helpers.val_to_float("not-a-number")))
        self.assertEqual(helpers.val_to_float(None, default=0), 0)

    def test_is_int_valid_integers(self):
        self.assertTrue(helpers.is_int("42"))
        self.assertTrue(helpers.is_int("0"))
        self.assertTrue(helpers.is_int(1))
        self.assertTrue(helpers.is_int(1.0))

    def test_is_int_invalid_inputs(self):
        self.assertFalse(helpers.is_int("1.5"))
        self.assertFalse(helpers.is_int("abc"))
        self.assertFalse(helpers.is_int(None))
        self.assertTrue(helpers.is_int(1.5))
        self.assertFalse(helpers.is_int(wildcard))

    def test_is_wildcard_obj_by_type_and_code(self):
        G = MagicMock()
        obj1 = 1
        obj2 = 2
        obj3 = 3
        obj4 = 4
        
        G.get_node_attr.side_effect = lambda x: {
            1: {"type": "object", "code": wildcard},
            2: {"type": "array", "code": wildcard},
            3: {"type": "number", "code": wildcard},
            4: {"type": wildcard},
        }.get(x, {})
        
        self.assertTrue(helpers.is_wildcard_obj(G, obj1))
        self.assertTrue(helpers.is_wildcard_obj(G, obj2))
        self.assertTrue(helpers.is_wildcard_obj(G, obj3))
        self.assertTrue(helpers.is_wildcard_obj(G, obj4))

    def test_is_wildcard_obj_non_wildcard(self):
        G = MagicMock()
        obj = 1
        
        G.get_node_attr.return_value = {"type": "object", "code": "not_wildcard"}
        self.assertFalse(helpers.is_wildcard_obj(G, obj))
        
        G.get_node_attr.return_value = {"type": "number", "code": 42}
        self.assertFalse(helpers.is_wildcard_obj(G, obj))


if __name__ == "__main__":
    unittest.main()
