import unittest

from probejs.core.trace_rule import TraceRule
from tests.units.vul_checking_fakes import FakeGraph


class TestTraceRuleNew(unittest.TestCase):
    def test_trace_rule_new_start_end_funcs(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
        }
        name_map = {100: "handler", 200: "sink_hqbpillvul_http_write"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            name_map=name_map,
        )
        path = [1, 2]

        self.assertTrue(TraceRule("start_with_func", ["handler"], graph).check(path))
        self.assertTrue(
            TraceRule("end_with_func", ["sink_hqbpillvul_http_write"], graph).check(
                path
            )
        )
        self.assertTrue(
            TraceRule("not_start_with_func", ["sink_hqbpillvul_http_write"], graph).check(
                path
            )
        )

    def test_trace_rule_new_start_with_var(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
        }
        name_map = {1: "OPGen_TAINTED_VAR_url", 100: "handler", 200: "pipe"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            name_map=name_map,
        )
        path = [1, 2]

        self.assertTrue(
            TraceRule("start_with_var", ["OPGen_TAINTED_VAR_url"], graph).check(path)
        )

    def test_trace_rule_new_start_within_file_and_not_start_within_file(self):
        node_attrs = {
            1: {"funcid:int": 100},
        }
        name_map = {100: "handler"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            name_map=name_map,
            file_paths={1: "/tmp/app.js"},
        )
        path = [1]

        self.assertTrue(TraceRule("start_within_file", ["app.js"], graph).check(path))
        self.assertTrue(
            TraceRule("not_start_within_file", ["child_process.js"], graph).check(path)
        )

    def test_trace_rule_new_has_user_input_from_edges(self):
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

        self.assertTrue(TraceRule("has_user_input", None, graph).check(path))

    def test_trace_rule_new_has_user_input_file_fallback(self):
        graph = FakeGraph(
            new_trace_rule=True,
            file_paths={1: "/tmp/http.js"},
            node_attrs={1: {"funcid:int": 100}},
            name_map={100: "handler"},
        )
        self.assertTrue(TraceRule("has_user_input", None, graph).check([1]))


if __name__ == "__main__":
    unittest.main()
