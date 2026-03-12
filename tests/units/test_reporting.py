import json
import tempfile
import unittest
from types import SimpleNamespace

from jsflow.reporting import build_analysis_report, write_reports
from jsflow.vuln.vul_checking import vul_checking
from tests.units.vul_checking_fakes import FakeGraph


class TestReporting(unittest.TestCase):
    def _build_graph(self):
        node_attrs = {
            1: {
                "funcid:int": 100,
                "lineno:int": "10",
                "endlineno:int": "10",
                "labels:label": "AST_CALL",
                "type": "AST_CALL",
            },
            2: {
                "funcid:int": 200,
                "lineno:int": "20",
                "endlineno:int": "20",
                "labels:label": "AST_CALL",
                "type": "AST_CALL",
            },
            300: {"tainted": True},
        }
        edge_attrs = {(1, 2): {0: {"type:TYPE": "OBJ_REACHES", "obj": 300}}}
        file_paths = {1: "/tmp/app.js", 2: "/tmp/app.js"}
        line_codes = {1: "const cmd = input;", 2: "exec(cmd);"}
        name_map = {100: "handler", 200: "child_process.execSync"}
        graph = FakeGraph(
            new_trace_rule=True,
            node_attrs=node_attrs,
            edge_attrs=edge_attrs,
            file_paths=file_paths,
            name_map=name_map,
            line_codes=line_codes,
        )
        graph.vul_type = "os_command"
        graph.auto_exploit = True
        graph.success_exploit = True
        graph.entry_file_path = "/tmp/app.js"
        graph.covered_stat = {1, 2}
        graph.covered_func = {100, 200}
        graph.num_of_cf_paths = 1
        graph.num_of_full_cf_paths = 1
        graph.exploit_reports = [
            {
                "sink_function": "child_process.execSync",
                "source_name": "input",
                "payload": "; touch /tmp/poc",
                "status": "solved",
                "bindings": [
                    {
                        "symbol": "s1",
                        "name": "input",
                        "value": "; touch /tmp/poc",
                        "role": "input",
                    }
                ],
            }
        ]
        return graph

    def test_vul_checking_returns_diagnostics(self):
        graph = self._build_graph()
        matched, diagnostics = vul_checking(graph, [[1, 2]], "os_command", return_diagnostics=True)
        self.assertEqual(matched, [[1, 2]])
        self.assertEqual(len(diagnostics), 1)
        self.assertTrue(diagnostics[0]["matched"])
        self.assertEqual(diagnostics[0]["matched_rule_list"], 0)
        self.assertTrue(diagnostics[0]["rule_lists"][0]["rules"][0]["passed"])

    def test_json_reports_are_written(self):
        graph = self._build_graph()
        graph.success_detect = True
        _, diagnostics = vul_checking(graph, [[1, 2]], "os_command", return_diagnostics=True)
        args = SimpleNamespace(input_file="/tmp/app.js", module=True)
        report = build_analysis_report(
            graph,
            args,
            started_at=0,
            candidate_paths=[[1, 2]],
            rule_diagnostics=diagnostics,
            exploit_reports=graph.exploit_reports,
        )

        self.assertEqual(report["summary"]["matched_findings"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["source"]["function"], "handler")
        self.assertIn("exec(cmd)", report["findings"][0]["sink"]["snippet"]["text"])
        self.assertEqual(report["findings"][0]["path"]["nodes"][0]["id"], "1")
        self.assertEqual(
            report["findings"][0]["poc_guidance"]["public_entrypoint"]["symbol"],
            "input",
        )
        self.assertEqual(
            report["findings"][0]["poc_guidance"]["application_sink"]["symbol"],
            "child_process.execSync",
        )
        self.assertEqual(
            report["findings"][0]["poc_guidance"]["validation"]["status"],
            "not_run",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_reports(report, tmpdir, emit_json=True)
            self.assertIn("schema", written)
            self.assertIn("json", written)

            with open(written["json"], "r", encoding="utf-8") as handle:
                json_report = json.load(handle)

            self.assertEqual(json_report["summary"]["detection_status"], "successful")
            self.assertEqual(json_report["version"], "1.1.0")


if __name__ == "__main__":
    unittest.main()
