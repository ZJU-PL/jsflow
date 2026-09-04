import json
import os
import subprocess
import sys
import tempfile
import unittest


class TestTypeScriptAnalysis(unittest.TestCase):
    def run_probejs(self, entry, report_dir):
        subprocess.run(
            [
                sys.executable,
                "-m",
                "probejs",
                "--json",
                "--report-dir",
                report_dir,
                "-t",
                "os_command",
                entry,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        with open(os.path.join(report_dir, "report.json"), encoding="utf-8") as fp:
            return json.load(fp)

    def test_os_command_flow_is_detected_in_typescript(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "vulnerable.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { exec } from 'child_process';\n"
                    "const command: string = process.argv[2];\n"
                    "exec(command);\n"
                )

            report_dir = os.path.join(temp_dir, "report")
            report = self.run_probejs(entry, report_dir)

            self.assertEqual(report["summary"]["matched_findings"], 1)
            finding = next(item for item in report["findings"] if item["status"] == "matched")
            self.assertEqual(finding["source"]["file"], entry)
            self.assertEqual(finding["source"]["line"], 2)
            self.assertEqual(finding["poc"]["sink"]["file"], entry)
            self.assertEqual(finding["poc"]["sink"]["line"], 3)

    def test_taint_flows_across_tsconfig_path_alias(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = os.path.join(temp_dir, "src")
            os.makedirs(source_dir)
            entry = os.path.join(source_dir, "main.ts")
            source = os.path.join(source_dir, "source.ts")
            with open(os.path.join(temp_dir, "tsconfig.json"), "w", encoding="utf-8") as fp:
                fp.write(
                    '{"compilerOptions":{"baseUrl":".",'
                    '"paths":{"@app/*":["src/*"]}}}'
                )
            with open(source, "w", encoding="utf-8") as fp:
                fp.write(
                    "export function getCommand(): string {\n"
                    "  return process.argv[2];\n"
                    "}\n"
                )
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { exec } from 'child_process';\n"
                    "import { getCommand } from '@app/source';\n"
                    "exec(getCommand());\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertEqual(report["summary"]["matched_findings"], 1)
            finding = next(item for item in report["findings"] if item["status"] == "matched")
            self.assertEqual(finding["source"]["file"], source)
            self.assertEqual(finding["source"]["line"], 2)
            self.assertEqual(finding["poc"]["sink"]["file"], entry)
            self.assertEqual(finding["poc"]["sink"]["line"], 3)

    def test_typed_registration_callback_is_analyzed_without_a_runtime_model(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "callback.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "declare function register(callback: () => void): void;\n"
                    "import { exec } from 'child_process';\n"
                    "register(() => exec(process.argv[2]));\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertEqual(report["summary"]["matched_findings"], 1)

    def test_arkts_entry_component_requires_vendor_compilation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "Index.ets")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { exec } from 'child_process';\n"
                    "@Entry\n@Component\nstruct Index {\n"
                    "  build() {\n"
                    "    Column() {\n"
                    "      exec(process.argv[2])\n"
                    "    }\n"
                    "  }\n"
                    "}\n"
                )

            result = subprocess.run(
                [sys.executable, "-m", "probejs", "-t", "os_command", entry],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ArkTS .ets input is not supported", result.stderr)

    def test_frontend_diagnostics_are_in_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "diagnostic.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("const value: string = 42; void value;\n")

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertGreater(report["summary"]["frontend_errors"], 0)
            self.assertTrue(any(
                diagnostic["code"] == "TS2322"
                for diagnostic in report["frontend"]["diagnostics"]
            ))
            self.assertTrue(report["frontend"]["compilers"])

    def test_callback_property_from_declaration_is_invoked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "options.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "declare function configure(options: { handler: () => void }): void;\n"
                    "import { exec } from 'child_process';\n"
                    "configure({ handler: () => exec(process.argv[2]) });\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertEqual(report["summary"]["matched_findings"], 1)

    def test_fastify_route_handler_model_is_invoked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "fastify.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import fastify from 'fastify';\n"
                    "import { exec } from 'child_process';\n"
                    "fastify().get('/run', (request: unknown) => exec(request as string));\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertGreaterEqual(report["summary"]["matched_findings"], 1)

    def test_exported_lambda_handler_is_treated_as_entrypoint(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "lambda.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { exec } from 'child_process';\n"
                    "export function handler(event: string): void { exec(event); }\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertEqual(report["summary"]["matched_findings"], 1)

    def test_event_listener_receives_tainted_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "events.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { EventEmitter } from 'events';\n"
                    "import { exec } from 'child_process';\n"
                    "new EventEmitter().on('data', (data: string) => exec(data));\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertEqual(report["summary"]["matched_findings"], 1)

    def test_nestjs_decorated_controller_method_is_analyzed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "nest.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { Controller, Get } from '@nestjs/common';\n"
                    "import { exec } from 'child_process';\n"
                    "@Controller()\n"
                    "class DemoController {\n"
                    "  @Get() run(value: string): void { exec(value); }\n"
                    "}\n"
                )

            report = self.run_probejs(entry, os.path.join(temp_dir, "report"))

            self.assertGreaterEqual(report["summary"]["matched_findings"], 1)


if __name__ == "__main__":
    unittest.main()
