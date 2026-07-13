import unittest
from unittest.mock import MagicMock, patch
from collections import defaultdict

from probejs.core.solver import MixedSymbol, check_number_operation, check_string_operation


class TestMixedSymbol(unittest.TestCase):
    def test_mixed_symbol_default_type(self):
        sym = MixedSymbol("test_obj")
        self.assertIsNotNone(sym.number())
        self.assertIsNotNone(sym.string())

    def test_mixed_symbol_number_type(self):
        sym = MixedSymbol("test_obj", _type="number")
        self.assertIsNotNone(sym.number())
        self.assertIsNone(sym.string())

    def test_mixed_symbol_string_type(self):
        sym = MixedSymbol("test_obj", _type="string")
        self.assertIsNone(sym.number())
        self.assertIsNotNone(sym.string())


class TestCheckNumberOperation(unittest.TestCase):
    def test_all_mixed_symbols_with_numbers(self):
        arr = [
            MixedSymbol("1", _type="number"),
            MixedSymbol("2", _type="number")
        ]
        self.assertTrue(check_number_operation(arr))

    def test_mixed_symbols_with_none_number(self):
        arr = [
            MixedSymbol("1", _type="string"),
            MixedSymbol("2", _type="number")
        ]
        self.assertFalse(check_number_operation(arr))

    def test_non_mixed_symbol_in_array(self):
        arr = [
            MixedSymbol("1", _type="number"),
            "not a symbol"
        ]
        self.assertFalse(check_number_operation(arr))

    def test_empty_array(self):
        self.assertTrue(check_number_operation([]))


class TestCheckStringOperation(unittest.TestCase):
    def test_all_mixed_symbols_with_strings(self):
        arr = [
            MixedSymbol("1", _type="string"),
            MixedSymbol("2", _type="string")
        ]
        self.assertTrue(check_string_operation(arr))

    def test_mixed_symbols_with_none_string(self):
        arr = [
            MixedSymbol("1", _type="number"),
            MixedSymbol("2", _type="string")
        ]
        self.assertFalse(check_string_operation(arr))

    def test_non_mixed_symbol_in_array(self):
        arr = [
            MixedSymbol("1", _type="string"),
            "not a symbol"
        ]
        self.assertFalse(check_string_operation(arr))

    def test_empty_array(self):
        self.assertTrue(check_string_operation([]))


if __name__ == "__main__":
    unittest.main()
