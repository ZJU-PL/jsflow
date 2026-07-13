import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from probejs.reporting import build_analysis_report, write_reports
from probejs.vuln.vul_checking import vul_checking
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
        with tempfile.TemporaryDirectory() as package_root:
            entry_path = Path(package_root) / "app.js"
            lines = ["\n"] * 25
            lines[0] = "const child_process = require('child_process');\n"
            lines[4] = "module.exports.run = function(payload) {\n"
            lines[9] = "  const cmd = payload;\n"
            lines[19] = "  child_process.execSync(cmd);\n"
            lines[20] = "};\n"
            entry_path.write_text("".join(lines), encoding="utf-8")
            (Path(package_root) / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {"build": "node build.js"},
                        "engines": {"node": ">=18"},
                    }
                ),
                encoding="utf-8",
            )

            graph = self._build_graph()
            graph.success_detect = True
            graph.entry_file_path = str(entry_path)
            graph.file_paths = {1: str(entry_path), 2: str(entry_path)}
            _, diagnostics = vul_checking(graph, [[1, 2]], "os_command", return_diagnostics=True)
            args = SimpleNamespace(input_file=str(entry_path), module=True)
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
        self.assertIn("execSync(cmd)", report["findings"][0]["sink"]["snippet"]["text"])
        self.assertEqual(report["findings"][0]["path"]["nodes"][0]["id"], "1")
        self.assertEqual(
            report["findings"][0]["poc_guidance"]["public_entrypoint"]["symbol"],
            "module.exports.run",
        )
        self.assertEqual(report["findings"][0]["poc"]["finding_id"], "probejs/os_command/1")
        self.assertEqual(report["findings"][0]["poc"]["normalized_from"], "report")
        self.assertEqual(report["findings"][0]["poc"]["source"]["symbol"], "module.exports.run")
        self.assertEqual(
            report["findings"][0]["poc"]["constraints"]["payload_candidates"][0]["candidate"],
            "; touch /tmp/poc",
        )
        self.assertEqual(
            report["findings"][0]["poc_guidance"]["application_sink"]["symbol"],
            "child_process.execSync",
        )
        self.assertEqual(
            report["findings"][0]["poc_guidance"]["validation"]["status"],
            "not_run",
        )
        poc = report["findings"][0]["poc"]
        self.assertEqual(poc["thin_slice"]["kind"], "hybrid_thin_slice")
        self.assertEqual(
            poc["thin_slice"]["source_slice"]["required_spans"][0]["role"],
            "source",
        )
        self.assertEqual(
            poc["entrypoint_contract"]["preferred_call"],
            "target.run(payload)",
        )
        self.assertEqual(poc["entrypoint_contract"]["require_path"], "./app.js")
        self.assertEqual(poc["payload_contract"]["payload"], "; touch /tmp/poc")
        self.assertIn("child_process.execSync", poc["runtime_environment"]["mock_recommended"])
        self.assertEqual(poc["runtime_environment"]["node_version_hint"], ">=18")
        self.assertTrue(poc["runtime_environment"]["needs_build"])
        self.assertEqual(poc["recommended_harness"]["template"], "direct-call.cjs.template")
        self.assertEqual(poc["validation_oracle"]["preferred"]["type"], "mock_sink_call")
        self.assertGreaterEqual(len(poc["agent_todo"]), 4)
        self.assertEqual(
            poc["agent_packet"]["purpose"],
            "Generate the smallest safe PoC harness for this probejs finding.",
        )
        self.assertEqual(poc["agent_packet"]["target"]["preferred_call"], "target.run(payload)")
        self.assertEqual(poc["agent_packet"]["payload"]["candidate"], "; touch /tmp/poc")
        self.assertLessEqual(len(poc["agent_packet"]["thin_slice_summary"]), 6)
        self.assertEqual(poc["confidence"]["payload"], "high")
        self.assertIn("agent_todo", report["findings"][0]["poc_guidance"])
        self.assertIn("agent_packet", report["findings"][0]["poc_guidance"])

        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_reports(report, tmpdir, emit_json=True)
            self.assertIn("schema", written)
            self.assertIn("json", written)

            with open(written["json"], "r", encoding="utf-8") as handle:
                json_report = json.load(handle)

            self.assertEqual(json_report["summary"]["detection_status"], "successful")
            self.assertEqual(json_report["version"], "1.3.0")
            self.assertEqual(
                json_report["findings"][0]["poc"]["raw_probejs"]["report_finding_id"],
                "probejs/os_command/1",
            )


if __name__ == "__main__":
    unittest.main()
