import re
import unittest

from probejs.utils.utilities import (
    BranchTag,
    BranchTagContainer,
    DictCounter,
    get_random_hex,
    wildcard,
    _SpecialValue,
)


class TestUtilities(unittest.TestCase):
    def test_branch_tag_parsing_and_str(self):
        tag = BranchTag("If123#0A")
        self.assertEqual(tag.point, "If123")
        self.assertEqual(tag.branch, "0")
        self.assertEqual(tag.mark, "A")
        self.assertEqual(str(tag), "If123#0A")
        self.assertTrue(tag)

        empty_branch = BranchTag(point="If123")
        self.assertFalse(empty_branch)

    def test_branch_tag_container_queries(self):
        tags = BranchTagContainer(
            [
                BranchTag("If1#0A"),
                BranchTag("For2#1C"),
                BranchTag("Switch3#0D"),
                BranchTag("For4#0"),
            ]
        )
        self.assertEqual(tags.get_last_choice_tag(), BranchTag("Switch3#0D"))
        self.assertEqual(tags.get_last_for_tag(), BranchTag("For4#0"))
        self.assertEqual(tags.get_choice_tags(), BranchTagContainer(tags[:3:2]))
        self.assertEqual(tags.get_for_tags(), BranchTagContainer([tags[1], tags[3]]))
        self.assertEqual(tags.get_creating_for_tags(), BranchTagContainer([tags[1]]))

        tags.set_marks("X")
        self.assertTrue(all(tag.mark == "X" for tag in tags))

        matched = tags.get_matched_tags([BranchTag("If1#0X")], level=2)
        self.assertEqual(matched, BranchTagContainer([tags[0]]))
        idx, tag = tags.match(point="Switch3", branch="0")
        self.assertEqual(idx, 2)
        self.assertEqual(tag, tags[2])

    def test_dict_counter_and_random_hex(self):
        counter = DictCounter()
        counter["a"] += 1
        self.assertEqual(counter.gets("a"), "a:1")
        self.assertEqual(repr(counter), "DictCounter({'a': 1})")

        hex_value = get_random_hex(6)
        self.assertEqual(len(hex_value), 6)
        self.assertTrue(re.fullmatch(r"[0-9a-f]+", hex_value))

    def test_special_value_comparison(self):
        self.assertEqual(str(wildcard), "*")
        self.assertEqual(wildcard, _SpecialValue("*"))
        self.assertNotEqual(wildcard, _SpecialValue("other"))


if __name__ == "__main__":
    unittest.main()
