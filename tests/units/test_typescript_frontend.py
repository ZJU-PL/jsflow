import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from probejs.core import esprima


def node_rows(payload):
    nodes = payload.split("\n\n", 1)[0]
    return list(csv.DictReader(io.StringIO(nodes), dialect="excel-tab"))


class TestDirectTypeScriptFrontend(unittest.TestCase):
    def parse_source(self, source, suffix=".ts"):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "entry" + suffix)
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(source)
            return esprima.esprima_parse(entry, args=["-o", "-"])

    def test_frontend_keeps_original_source_and_emits_no_compiler_helpers(self):
        output = self.parse_source(
            "class Box { constructor(public value: string) {} }\n"
            "const box = new Box(process.argv[2]);\n"
            "box.value?.toString();\n"
        )

        self.assertIn("public value: string", output)
        self.assertIn("AST_CLASS", output)
        self.assertNotIn("__awaiter", output)
        self.assertNotIn("__decorate", output)
        self.assertNotIn("sourceMappingURL", output)

    def test_csv_output_is_deterministic(self):
        source = "export const value: string = process.argv[2];\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "entry.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(source)
            first = esprima.esprima_parse(entry, args=["-o", "-"])
            second = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertEqual(first, second)

    def test_exact_generic_callback_and_promise_metadata(self):
        output = self.parse_source(
            "declare function invoke<T>(value: T, callback: (value: T) => void): Promise<T>;\n"
            "invoke(1, value => console.log(value)); invoke('x', value => console.log(value));\n"
        )
        calls = [
            row for row in node_rows(output)
            if row["type"] == "AST_CALL" and row["typescript_callback_args"] == "1"
        ]

        self.assertEqual(len(calls), 2)
        self.assertTrue(all(row["typescript_promise_like:bool"] == "true" for row in calls))
        self.assertTrue(all("Promise" in row["typescript_return_type"] for row in calls))
        self.assertNotEqual(calls[0]["namespace"], calls[1]["namespace"])

    def test_enum_namespace_import_equals_and_export_assignment(self):
        output = self.parse_source(
            "import path = require('path');\n"
            "enum Mode { Safe, Unsafe }\n"
            "namespace Values { export const current = Mode.Safe; }\n"
            "export = { path, Values };\n"
        )

        self.assertIn("Mode.Safe", output)
        self.assertIn("Values.current", output)
        self.assertIn("module.exports", output)
        self.assertNotIn("TSEnumDeclaration", output)
        self.assertNotIn("TSModuleDeclaration", output)

    def test_static_fields_and_blocks_are_runtime_statements(self):
        output = self.parse_source(
            "class State { static value = source(); static { sink(State.value); } item = source(); }\n"
        )

        self.assertIn("State.value", output)
        self.assertIn("AST_CLASS", output)
        self.assertIn("source()", output)
        self.assertIn("sink(State.value)", output)
        self.assertNotIn("PropertyDefinition", output)
        self.assertNotIn("StaticBlock", output)

    def test_tsconfig_automatic_jsx_runtime_is_respected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "tsconfig.json"), "w", encoding="utf-8") as fp:
                fp.write('{"compilerOptions":{"jsx":"react-jsx","jsxImportSource":"preact"},'
                         '"include":["entry.tsx"]}')
            entry = os.path.join(temp_dir, "entry.tsx")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("export const view = <section>content</section>;\n")

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn("preact/jsx-runtime", output)
        self.assertIn("jsx", output)

    def test_module_flavors_and_dynamic_import_are_supported(self):
        for suffix in (".mts", ".cts"):
            with self.subTest(suffix=suffix):
                output = self.parse_source(
                    "async function load() { return import('./dependency.js'); }\n",
                    suffix=suffix,
                )
                self.assertIn("AST_FUNC_DECL", output)
                self.assertIn("./dependency.js", output)
                self.assertNotIn("ImportExpression", output)

    def test_workspace_source_package_is_in_the_runtime_graph(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = os.path.join(temp_dir, "packages", "shared")
            app_dir = os.path.join(temp_dir, "apps", "web")
            os.makedirs(os.path.join(package_dir, "src"))
            os.makedirs(app_dir)
            with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"private":true,"workspaces":["packages/*","apps/*"]}')
            with open(os.path.join(package_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"name":"@workspace/shared","source":"src/index.ts"}')
            shared = os.path.join(package_dir, "src", "index.ts")
            with open(shared, "w", encoding="utf-8") as fp:
                fp.write("export const value: number = 1;\n")
            entry = os.path.join(app_dir, "entry.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("import { value } from '@workspace/shared'; void value;\n")

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn(shared, output)
        self.assertIn("@workspace/shared", output)

    def test_mixed_typescript_and_javascript_project_uses_both_emitters(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            javascript = os.path.join(temp_dir, "source.js")
            entry = os.path.join(temp_dir, "entry.ts")
            with open(javascript, "w", encoding="utf-8") as fp:
                fp.write("exports.command = () => process.argv[2];\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { exec } from 'child_process';\n"
                    "import { command } from './source.js';\n"
                    "exec(command());\n"
                )

            report_dir = os.path.join(temp_dir, "report")
            subprocess.run(
                [sys.executable, "-m", "probejs", "--json", "--report-dir", report_dir,
                 "-t", "os_command", entry],
                check=True,
                capture_output=True,
                text=True,
            )
            with open(os.path.join(report_dir, "report.json"), encoding="utf-8") as fp:
                report = json.load(fp)

        self.assertEqual(report["summary"]["matched_findings"], 1)

    def test_declaration_only_package_is_not_emitted_as_runtime_javascript(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = os.path.join(temp_dir, "node_modules", "types-only")
            os.makedirs(package_dir)
            declaration = os.path.join(package_dir, "index.d.ts")
            with open(os.path.join(package_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"name":"types-only","types":"index.d.ts"}')
            with open(declaration, "w", encoding="utf-8") as fp:
                fp.write("export declare function value(): string;\n")
            entry = os.path.join(temp_dir, "entry.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("import { value } from 'types-only'; value();\n")

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        file_rows = [row for row in node_rows(output) if row["labels:label"] == "Filesystem"]
        self.assertFalse(any(row["name"].endswith(".d.ts") for row in file_rows))

    def test_specifier_level_type_only_import_has_no_runtime_require(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dependency = os.path.join(temp_dir, "types.ts")
            entry = os.path.join(temp_dir, "entry.ts")
            with open(dependency, "w", encoding="utf-8") as fp:
                fp.write("export interface Shape { value: string }\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("import { type Shape } from './types'; const value: Shape | null = null;\n")

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertNotIn(dependency, output)
        self.assertFalse(any(row["type"] == "AST_CALL" and "./types" in row["code"]
                             for row in node_rows(output)))

    def test_javascript_input_still_routes_to_original_frontend(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "entry.js")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("const value = 1;\n")
            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn("AST_ASSIGN", output)
        self.assertNotIn("typescript_compiler.js", output)

    def test_mixed_directory_includes_typescript_and_javascript_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            typescript = os.path.join(temp_dir, "typed.ts")
            javascript = os.path.join(temp_dir, "plain.js")
            with open(typescript, "w", encoding="utf-8") as fp:
                fp.write("export const typed: number = 1;\n")
            with open(javascript, "w", encoding="utf-8") as fp:
                fp.write("exports.plain = 2;\n")

            output = esprima.esprima_parse(temp_dir, args=["-o", "-"])

        self.assertIn(typescript, output)
        self.assertIn(javascript, output)

    def test_directory_uses_each_files_nearest_tsconfig(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            files = []
            configs = []
            for package in ("first", "second"):
                package_dir = os.path.join(temp_dir, "packages", package)
                os.makedirs(package_dir)
                config = os.path.join(package_dir, "tsconfig.json")
                source = os.path.join(package_dir, "index.ts")
                with open(config, "w", encoding="utf-8") as fp:
                    fp.write('{"compilerOptions":{"target":"ES2022"},"include":["index.ts"]}')
                with open(source, "w", encoding="utf-8") as fp:
                    fp.write(f"export const name: string = '{package}';\n")
                configs.append(config)
                files.append(source)

            output = esprima.esprima_parse(temp_dir, args=["-o", "-"])

        for source in files:
            self.assertIn(source, output)
        for config in configs:
            self.assertIn(config, output)


if __name__ == "__main__":
    unittest.main()
