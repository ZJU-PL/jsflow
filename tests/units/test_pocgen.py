import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from pocgen.agent_runner import _text_output as agent_text_output
from pocgen.agent_runner import AgentRunError, build_command, redact_command, run_agent
from pocgen.evidence import evidence_for_stage, render_json
from pocgen.generate import _overall_status, build_prompt, write_json
from pocgen.packet import extract_agent_packet, extract_poc, load_report, select_finding, target_cwd
from pocgen.validate import _text_output as validation_text_output
from pocgen.validate import default_command, validate_output


class TestPocgen(unittest.TestCase):
    def _write_report(self, root: Path) -> Path:
        package_root = root / "pkg"
        package_root.mkdir()
        (package_root / "index.js").write_text(
            "module.exports.run = function (payload) { return payload; };\n",
            encoding="utf-8",
        )
        report = {
            "$schema": "./report.schema.json",
            "version": "1.3.0",
            "tool": {"name": "jsflow"},
            "run": {
                "input_file": str(package_root / "index.js"),
                "entry_file": str(package_root / "index.js"),
                "vulnerability_type": "os_command",
                "auto_exploit": True,
                "log_dir": str(root / "logs"),
            },
            "summary": {"detection_status": "successful", "exploit_status": "successful", "total_findings": 1},
            "findings": [
                {
                    "id": "jsflow/os_command/1",
                    "status": "matched",
                    "message": "matched",
                    "poc": {
                        "finding_id": "jsflow/os_command/1",
                        "vulnerability_type": "os_command",
                        "target": {
                            "require_path": "./index.js",
                            "entry_file": "index.js",
                        },
                        "environment": {"cwd": str(package_root)},
                        "agent_packet": {
                            "purpose": "Generate the smallest safe PoC harness for this jsflow finding.",
                            "finding_id": "jsflow/os_command/1",
                            "vulnerability_type": "os_command",
                            "target": {
                                "cwd": str(package_root),
                                "require_path": "./index.js",
                                "module_system": "commonjs",
                                "preferred_call": "target.run(payload)",
                            },
                            "payload": {
                                "source_binding": "module.exports.run",
                                "candidate": "; echo JSFLOW_POC_SUCCESS #",
                                "expectation": "payload reaches command sink",
                            },
                            "sink": {"symbol": "child_process.execSync"},
                            "validation": {"type": "mock_sink_call"},
                            "runtime": {"mock_recommended": ["child_process.execSync"]},
                            "thin_slice_summary": [],
                            "todo": ["create PoC"],
                            "uncertainty": [],
                        },
                        "thin_slice": {"kind": "hybrid_thin_slice"},
                        "trace": {"nodes": []},
                        "payload_contract": {"payload": "; echo JSFLOW_POC_SUCCESS #"},
                        "validation_oracle": {"preferred": {"type": "mock_sink_call"}},
                    },
                    "path": {"node_ids": []},
                    "rule_evaluation": {"matched": True},
                    "exploit_candidates": [],
                }
            ],
        }
        report_path = root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return report_path

    def test_extract_packet_and_evidence_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = load_report(self._write_report(Path(tmp)))
            finding = select_finding(report, 0)
            packet = extract_agent_packet(finding)
            self.assertEqual(packet["target"]["preferred_call"], "target.run(payload)")
            self.assertEqual(packet["payload"]["candidate"], "; echo JSFLOW_POC_SUCCESS #")

            self.assertEqual(evidence_for_stage(finding, stage=0)["contents"], {})
            self.assertIn("thin_slice", evidence_for_stage(finding, stage=1)["contents"])
            self.assertIn("rule_evaluation", evidence_for_stage(finding, stage=2)["contents"])
            self.assertIn("finding", evidence_for_stage(finding, stage=3)["contents"])

    def test_legacy_packet_fallback_handles_empty_candidate_calls(self):
        finding = {
            "id": "legacy/1",
            "poc": {
                "finding_id": "legacy/1",
                "target": {},
                "invocation": {"candidate_calls": []},
            },
        }
        packet = extract_agent_packet(finding)
        self.assertEqual(packet["target"]["preferred_call"], "")

    def test_legacy_packet_fallback_accepts_string_candidate_call(self):
        finding = {
            "id": "legacy/1",
            "poc": {
                "finding_id": "legacy/1",
                "target": {},
                "invocation": {"candidate_calls": "target.run(payload)"},
            },
        }
        packet = extract_agent_packet(finding)
        self.assertEqual(packet["target"]["preferred_call"], "target.run(payload)")

    def test_legacy_packet_fallback_ignores_bad_nested_field_types(self):
        finding = {
            "id": "legacy/1",
            "poc": {
                "finding_id": "legacy/1",
                "environment": "bad",
                "target": "bad",
                "invocation": "bad",
                "source": "bad",
                "constraints": "bad",
            },
        }
        packet = extract_agent_packet(finding)
        self.assertEqual(packet["target"]["cwd"], None)
        self.assertEqual(packet["target"]["preferred_call"], "")
        self.assertIsNone(packet["payload"]["candidate"])

    def test_target_cwd_file_value_resolves_to_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = self._write_report(Path(tmp))
            report = load_report(report_path)
            finding = select_finding(report, 0)
            poc = extract_poc(finding)
            index_path = Path(tmp) / "pkg" / "index.js"
            poc["agent_packet"]["target"]["cwd"] = str(index_path)
            self.assertEqual(target_cwd(report, poc, report_path), index_path.parent.resolve())

    def test_target_cwd_ignores_bad_nested_field_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            report = {"run": "bad"}
            poc = {
                "agent_packet": "bad",
                "runtime_environment": "bad",
                "environment": "bad",
                "target": "bad",
            }
            self.assertEqual(target_cwd(report, poc, report_path), report_path.parent.resolve())

    def test_target_cwd_ignores_non_path_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            report = {"run": {"entry_file": {"bad": "path"}, "input_file": 12}}
            poc = {
                "agent_packet": {"target": {"cwd": ["bad"]}},
                "runtime_environment": {"cwd": {"bad": "path"}},
                "environment": {"cwd": 42},
                "target": {"entry_file": ["bad"]},
            }
            self.assertEqual(target_cwd(report, poc, report_path), report_path.parent.resolve())

    def test_prompt_includes_target_cwd_import_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = self._write_report(Path(tmp))
            report = load_report(report_path)
            finding = select_finding(report, 0)
            packet = extract_agent_packet(finding)
            target_root = Path(tmp) / "pkg"
            prompt = build_prompt(
                agent_packet=packet,
                evidence={"stage": 0, "contents": {}},
                output_dir=Path(tmp) / "out",
                target_cwd=target_root,
                report_path=report_path,
                finding_selector="0",
            )
            self.assertIn(str(target_root), prompt)
            self.assertIn("JavaScript imports", prompt)
            self.assertIn("resolve relative to the PoC", prompt)
            self.assertIn("resolve it from the target package root", prompt)

    def test_json_helpers_handle_non_json_native_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "data.json"
            write_json(
                output,
                {
                    1: "numeric key",
                    "path": root / "pkg",
                    "bytes": b"abc",
                    "set": {"b", "a"},
                },
            )
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["1"], "numeric key")
            self.assertEqual(data["bytes"], "abc")
            self.assertEqual(data["path"], str(root / "pkg"))
            self.assertEqual(data["set"], ["a", "b"])
            self.assertIn(str(root / "pkg"), render_json({1: root / "pkg"}))

    def test_generate_dry_run_writes_packet_and_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_dir = root / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(output_dir),
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((output_dir / "agent_packet.json").exists())
            self.assertTrue((output_dir / "finding_poc.json").exists())
            self.assertTrue((output_dir / "prompt-stage-0.md").exists())
            result = json.loads((output_dir / "pocgen-result.json").read_text())
            self.assertEqual(result["status"], "dry_run")
            self.assertEqual(result["attempts"][0]["evidence_stage"], 0)

    def test_generate_expands_tilde_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_dir = root / "out"
            env = os.environ.copy()
            env["HOME"] = str(root)
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    "~/report.json",
                    "--finding",
                    "0",
                    "--output",
                    "~/out",
                    "--codebase",
                    "~/pkg",
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((output_dir / "pocgen-result.json").read_text())
            self.assertEqual(result["report"], str(report_path.resolve()))
            self.assertEqual(result["output_dir"], str(output_dir.resolve()))
            self.assertEqual(result["target_cwd"], str((root / "pkg").resolve()))

    def test_generate_dry_run_records_validation_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_dir = root / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(output_dir),
                    "--validation-command",
                    "node custom-poc.js",
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((output_dir / "pocgen-result.json").read_text())
            self.assertEqual(result["validation_command"], ["node", "custom-poc.js"])

    def test_generate_dry_run_records_agent_repro_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_dir = root / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(output_dir),
                    "--agent",
                    "codex",
                    "--model",
                    "default",
                    "--agent-arg=--model",
                    "--agent-arg",
                    "gpt-test",
                    "--max-repairs",
                    "4",
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((output_dir / "pocgen-result.json").read_text())
            self.assertEqual(result["agent"], "codex")
            self.assertEqual(result["model"], "default")
            self.assertEqual(result["agent_args"], ["--model", "gpt-test"])
            self.assertEqual(result["max_repairs"], 4)

    def test_blank_validation_command_is_treated_as_unspecified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_dir = root / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(output_dir),
                    "--validation-command",
                    "   ",
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((output_dir / "pocgen-result.json").read_text())
            self.assertIsNone(result["validation_command"])

    def test_invalid_validation_command_reports_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_dir = root / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(output_dir),
                    "--validation-command",
                    "node 'unterminated",
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("invalid --validation-command", proc.stderr)
            self.assertFalse(output_dir.exists())

    def test_invalid_numeric_options_report_cli_error(self):
        cases = [
            ("--timeout", "0", "--timeout must be greater than 0"),
            ("--validation-timeout", "0", "--validation-timeout must be greater than 0"),
            ("--max-repairs", "-1", "--max-repairs must be greater than or equal to 0"),
            (
                "--max-evidence-chars",
                "-1",
                "--max-evidence-chars must be greater than or equal to 0",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            for flag, value, message in cases:
                with self.subTest(flag=flag):
                    output_dir = root / f"out-{flag[2:]}"
                    proc = subprocess.run(
                        [
                            sys.executable,
                            "pocgen/generate.py",
                            "--report",
                            str(report_path),
                            "--finding",
                            "0",
                            "--output",
                            str(output_dir),
                            flag,
                            value,
                            "--dry-run",
                        ],
                        cwd=Path(__file__).resolve().parents[2],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn(message, proc.stderr)
                    self.assertFalse(output_dir.exists())

    def test_invalid_codebase_override_reports_cli_error_even_in_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            missing_codebase = root / "missing"
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(root / "out"),
                    "--codebase",
                    str(missing_codebase),
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--codebase must be an existing directory", proc.stderr)

    def test_output_file_path_reports_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_report(root)
            output_file = root / "out"
            output_file.write_text("not a directory", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    "pocgen/generate.py",
                    "--report",
                    str(report_path),
                    "--finding",
                    "0",
                    "--output",
                    str(output_file),
                    "--dry-run",
                ],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--output must be a directory", proc.stderr)

    def test_validate_output_detects_pass_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "poc.js").write_text("console.log('PASS');\n", encoding="utf-8")
            result = validate_output(root)
            self.assertEqual(result.status, "passed")
            self.assertEqual(result.returncode, 0)

    def test_validate_output_explicit_empty_command_does_not_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "poc.js").write_text("console.log('PASS');\n", encoding="utf-8")
            result = validate_output(root, command=[])
            self.assertEqual(result.status, "not_run")
            self.assertEqual(result.command, [])

    def test_validate_output_accepts_relative_output_dir(self):
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "out"
            output.mkdir()
            (output / "poc.js").write_text("console.log('PASS');\n", encoding="utf-8")
            try:
                os.chdir(root)
                result = validate_output("out")
            finally:
                os.chdir(original_cwd)
            self.assertEqual(result.status, "passed")
            self.assertEqual(result.returncode, 0)

    def test_validate_output_expands_tilde_output_dir(self):
        original_home = os.environ.get("HOME")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "out"
            output.mkdir()
            (output / "poc.js").write_text("console.log('PASS');\n", encoding="utf-8")
            os.environ["HOME"] = str(root)
            try:
                result = validate_output("~/out")
            finally:
                if original_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = original_home
            self.assertEqual(result.status, "passed")

    def test_validation_timeout_bytes_are_json_safe_text(self):
        self.assertEqual(validation_text_output(b"partial\n"), "partial\n")
        self.assertEqual(validation_text_output(None), "")

    def test_validate_output_does_not_match_pass_substrings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "poc.js").write_text("console.log('BYPASS');\n", encoding="utf-8")
            result = validate_output(root)
            self.assertEqual(result.status, "ran_no_oracle")

    def test_validate_output_requires_success_marker_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "poc.js").write_text(
                "console.log('expected PASS but sink was not reached');\n",
                encoding="utf-8",
            )
            result = validate_output(root)
            self.assertEqual(result.status, "ran_no_oracle")

    def test_default_command_ignores_unmodified_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = (
                Path(__file__).resolve().parents[2]
                / "pocgen"
                / "templates"
                / "direct-call.cjs"
            )
            (root / "direct-call.cjs").write_bytes(template.read_bytes())
            self.assertIsNone(default_command(root))

    def test_default_command_ignores_artifact_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "poc.js").mkdir()
            (root / "direct-call.cjs").mkdir()
            self.assertIsNone(default_command(root))

    def test_default_command_uses_modified_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "direct-call.cjs"
            artifact.write_text("console.log('PASS');\n", encoding="utf-8")
            command = default_command(root)
            self.assertIsNotNone(command)
            self.assertEqual(command[0], "node")
            self.assertEqual(Path(command[1]).resolve(), artifact.resolve())
            result = validate_output(root)
            self.assertEqual(result.status, "passed")

    def test_overall_status_distinguishes_unvalidated_generation(self):
        self.assertEqual(
            _overall_status([{"status": "agent_completed"}], {"status": "ran_no_oracle"}),
            "generated_unvalidated",
        )
        self.assertEqual(
            _overall_status([{"dry_run": True}], {"status": "not_run"}),
            "dry_run",
        )
        self.assertEqual(
            _overall_status([{"status": "agent_completed"}], {"status": "passed"}),
            "validated",
        )

    def test_agent_command_redacts_prompt(self):
        prompt = "large prompt with finding evidence"
        command = build_command(agent="codex", model="default", prompt=prompt)
        redacted = redact_command(command, prompt)
        self.assertIn("<prompt omitted; see prompt-stage-N.md>", redacted)
        self.assertNotIn(prompt, redacted)

    def test_agent_output_bytes_are_text(self):
        self.assertEqual(agent_text_output(b"agent partial\n"), "agent partial\n")
        self.assertEqual(agent_text_output(None), "")

    def test_codex_and_opencode_agent_args_precede_prompt(self):
        prompt = "build a poc"
        for agent in ("codex", "opencode"):
            with self.subTest(agent=agent):
                command = build_command(
                    agent=agent,
                    model="default",
                    prompt=prompt,
                    extra_args=["--model", "test-model"],
                )
                prompt_index = command.index(prompt)
                self.assertLess(command.index("--model"), prompt_index)
                self.assertLess(command.index("test-model"), prompt_index)

    def test_claude_prompt_stays_after_p_flag(self):
        prompt = "build a poc"
        command = build_command(
            agent="claude",
            model="claude-test",
            prompt=prompt,
            extra_args=["--verbose"],
        )
        self.assertEqual(command[command.index("-p") + 1], prompt)
        self.assertGreater(command.index("--verbose"), command.index(prompt))

    def test_claude_json_output_must_be_object(self):
        completed = subprocess.CompletedProcess(
            args=["claude"],
            returncode=0,
            stdout="[]",
            stderr="",
        )
        with tempfile.TemporaryDirectory() as tmp:
            with patch("pocgen.agent_runner.subprocess.run", return_value=completed):
                with self.assertRaisesRegex(AgentRunError, "JSON output root must be an object"):
                    run_agent(
                        "prompt",
                        cwd=tmp,
                        agent="claude",
                        model="claude-test",
                        timeout=1,
                    )


if __name__ == "__main__":
    unittest.main()
