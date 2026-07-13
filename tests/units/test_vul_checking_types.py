import unittest

from probejs.vuln.vul_checking import vul_checking
from tests.units.vul_checking_fakes import FakeGraph


class TestVulCheckingTypes(unittest.TestCase):
    def test_vul_checking_os_command_precision_recall(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            3: {"funcid:int": 300},
            301: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 301}}}
        name_map = {100: "handler", 200: "child_process.exec", 300: "parseInt"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
            file_paths={1: "/tmp/app.js"},
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "os_command")
        self.assertEqual(matched, [path])

        graph.file_paths = {1: "/tmp/child_process.js"}
        matched = vul_checking(graph, [path], "os_command")
        self.assertEqual(matched, [])

        graph.file_paths = {1: "/tmp/app.js"}
        matched = vul_checking(graph, [[1, 2, 3]], "os_command")
        self.assertEqual(matched, [])

    def test_vul_checking_code_exec_variants(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            3: {"funcid:int": 300},
            400: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 400}}}
        name_map = {100: "handler", 200: "eval", 300: "parseInt"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
            file_paths={1: "/tmp/app.js"},
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "code_exec")
        self.assertEqual(sorted({tuple(p) for p in matched}), [tuple(path)])

        graph.file_paths = {1: "/tmp/eval.js"}
        matched = vul_checking(graph, [path], "code_exec")
        self.assertEqual(sorted({tuple(p) for p in matched}), [tuple(path)])

        graph.file_paths = {1: "/tmp/app.js"}
        name_map[200] = "Function"
        matched = vul_checking(graph, [path], "code_exec")
        self.assertEqual(sorted({tuple(p) for p in matched}), [tuple(path)])

        matched = vul_checking(graph, [[1, 2, 3]], "code_exec")
        self.assertEqual(matched, [])

    def test_vul_checking_path_traversal_both_rule_lists(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            3: {"funcid:int": 201},
            4: {"funcid:int": 202},
        }
        name_map = {
            1: "OPGen_TAINTED_VAR_url",
            100: "handler",
            200: "sink_hqbpillvul_fs_read",
            201: "pipe",
            202: "sink_hqbpillvul_http_sendFile",
        }
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            name_map=name_map,
            file_paths={1: "/tmp/app.js"},
        )
        path_pipe = [1, 2, 3]

        matched = vul_checking(graph, [path_pipe], "path_traversal")
        self.assertEqual(matched, [path_pipe])

        matched = vul_checking(graph, [[1, 4]], "path_traversal")
        self.assertEqual(matched, [[1, 4]])

        graph.name_map[1] = "not_tainted_url"
        matched = vul_checking(graph, [path_pipe], "path_traversal")
        self.assertEqual(matched, [])

    def test_vul_checking_proto_pollution_precision_recall(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            3: {"funcid:int": 300},
            600: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 600}}}
        name_map = {100: "handler", 200: "merge", 300: "parseInt"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "proto_pollution")
        self.assertEqual(matched, [path])

        matched = vul_checking(graph, [[1, 2, 3]], "proto_pollution")
        self.assertEqual(matched, [])

    def test_vul_checking_nosql_precision_recall(self):
        node_attrs = {
            1: {"funcid:int": 100},
            2: {"funcid:int": 200},
            3: {"funcid:int": 300},
            700: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 700}}}
        name_map = {100: "handler", 200: "sink_hqbpillvul_nosql", 300: "parseInt"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            name_map=name_map,
            file_paths={1: "/tmp/app.js"},
        )
        path = [1, 2]

        matched = vul_checking(graph, [path], "nosql")
        self.assertEqual(matched, [path])

        graph.file_paths = {1: "/tmp/mongodb.js"}
        matched = vul_checking(graph, [path], "nosql")
        self.assertEqual(matched, [])

        graph.file_paths = {1: "/tmp/app.js"}
        matched = vul_checking(graph, [[1, 2, 3]], "nosql")
        self.assertEqual(matched, [])


if __name__ == "__main__":
    unittest.main()
