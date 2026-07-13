import unittest

from probejs.vuln.vul_checking import do_vul_checking, vul_checking
from tests.units.vul_checking_fakes import FakeGraph


class TestVulCheckingCore(unittest.TestCase):
    def test_do_vul_checking_filters_paths(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            3: {"funcid:int": 100},
            4: {"funcid:int": 200},
            300: {"tainted": True},
            301: {"tainted": False},
        }
        edge_attrs = {
            (1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}},
            (3, 4): {0: {"type:TYPE": "OBJ_REACHES", "obj": 301}},
        }
        name_map = {100: "handler", 200: "sink_hqbpillvul_http_write"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
        )
        path_good = [1, 2]
        path_bad = [3, 4]

        rule_list = [
            ("has_user_input", None),
            ("end_with_func", ["sink_hqbpillvul_http_write"]),
        ]
        matched = do_vul_checking(graph, rule_list, [path_good, path_bad])
        self.assertEqual(matched, [path_good])

    def test_vul_checking_xss_rules_match_write(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            300: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}}}
        name_map = {100: "handler", 200: "sink_hqbpillvul_http_write"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "xss")
        self.assertEqual(matched, [path])

    def test_vul_checking_xss_rules_match_set_header(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            300: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}}}
        name_map = {100: "handler", 200: "sink_hqbpillvul_http_setHeader"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "xss")
        self.assertEqual(matched, [path])

    def test_vul_checking_xss_rejects_starting_at_sink(self):
        node_attrs = {
            1: {"funcid:int": 200},
            2: {"funcid:int": 200},
            300: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}}}
        name_map = {200: "sink_hqbpillvul_http_write"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "xss")
        self.assertEqual(matched, [])


if __name__ == "__main__":
    unittest.main()
