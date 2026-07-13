import math
import unittest

from probejs.utils import helpers
from probejs.utils.utilities import wildcard, undefined


class TestHelpers(unittest.TestCase):
    def test_val_to_str_numbers_and_defaults(self):
        self.assertEqual(helpers.val_to_str(3.5), "3.5")
        self.assertEqual(helpers.val_to_str(2), "2")
        self.assertIs(helpers.val_to_str(None), wildcard)
        self.assertEqual(helpers.val_to_str(None, default="x"), "x")

    def test_val_to_float_special_values(self):
        self.assertIs(helpers.val_to_float(None), wildcard)
        self.assertIs(helpers.val_to_float(wildcard), wildcard)
        self.assertIs(helpers.val_to_float(undefined), wildcard)
        self.assertEqual(helpers.val_to_float("3.25"), 3.25)
        self.assertTrue(math.isnan(helpers.val_to_float("not-a-number")))

    def test_js_cmp_respects_types(self):
        self.assertEqual(helpers.js_cmp("2", "10"), 1)  # string compare
        self.assertEqual(helpers.js_cmp("2", 10), -1)  # numeric compare
        self.assertEqual(helpers.js_cmp(undefined, undefined), 0)

    def test_is_int(self):
        self.assertTrue(helpers.is_int("1"))
        self.assertTrue(helpers.is_int(1.2))
        self.assertFalse(helpers.is_int("1.2"))
        self.assertFalse(helpers.is_int(None))


if __name__ == "__main__":
    unittest.main()
