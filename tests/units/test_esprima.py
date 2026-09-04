import unittest
from unittest.mock import MagicMock, patch, Mock
import os
import tempfile
import json
import base64

from probejs.core import esprima
from probejs._setup import get_builtin_packages_dir


class TestEsprimaParse(unittest.TestCase):
    @patch('subprocess.Popen')
    def test_esprima_parse_basic(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_proc
        
        result = esprima.esprima_parse("test.js")
        self.assertEqual(result, "output")
        
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[0], "node")
        self.assertTrue("test.js" in args)

    @patch('subprocess.Popen')
    def test_esprima_parse_with_args(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_proc
        
        result = esprima.esprima_parse("test.js", args=["--option1", "--option2"])
        self.assertEqual(result, "output")
        
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[0], "node")
        self.assertIn("--option1", args)
        self.assertIn("--option2", args)

    @patch('subprocess.Popen')
    def test_esprima_parse_with_input(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "")
        mock_popen.return_value = mock_proc
        
        input_code = "const x = 1;"
        result = esprima.esprima_parse("-", input=input_code)
        self.assertEqual(result, "output")
        
        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[2], "-")

    @patch('subprocess.Popen')
    def test_esprima_parse_stderr_handling(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("output", "error message")
        mock_popen.return_value = mock_proc
        
        print_func = Mock()
        result = esprima.esprima_parse("test.js", print_func=print_func)
        
        self.assertEqual(result, "output")
        print_func.assert_called_once_with("error message")

    @patch('subprocess.Popen')
    def test_esprima_parse_failure_is_not_silent(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", "syntax error")
        mock_proc.returncode = 1
        mock_popen.return_value = mock_proc

        with self.assertRaisesRegex(RuntimeError, "syntax error"):
            esprima.esprima_parse("broken.ts")

    @patch('subprocess.Popen')
    def test_esprima_search(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("/path/to/main.js\n/path/to/module.js\n", "")
        mock_popen.return_value = mock_proc
        
        main_path, module_path = esprima.esprima_search("express", "/path/to/search")
        
        self.assertEqual(main_path, "/path/to/main.js")
        self.assertEqual(module_path, "/path/to/module.js")

    @patch('subprocess.Popen')
    def test_esprima_search_with_print_func(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("/main.js\n/module.js\n", "search error")
        mock_popen.return_value = mock_proc
        
        print_func = Mock()
        main_path, module_path = esprima.esprima_search(
            "module", "/path", print_func=print_func
        )
        
        print_func.assert_called_once_with("search error")

    @patch('subprocess.Popen')
    def test_get_file_list(self, mock_popen):
        stderr_output = """
        [\x1b[32mAnalyzing /path/to/file1.js\x1b[0m
        [\x1b[32mAnalyzing /path/to/file2.js\x1b[0m
        [\x1b[32mAnalyzing stdin\x1b[0m
        [\x1b[32mAnalyzing /path/to/file3.js\x1b[0m
        """
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", stderr_output)
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(len(result), 3)
        self.assertIn("/path/to/file1.js", result)
        self.assertIn("/path/to/file2.js", result)
        self.assertIn("/path/to/file3.js", result)
        self.assertNotIn("stdin", result)

    @patch('subprocess.Popen')
    def test_get_file_list_empty(self, mock_popen):
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", "")
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(result, [])

    @patch('subprocess.Popen')
    def test_get_file_list_only_stdin(self, mock_popen):
        stderr_output = "[\x1b[32mAnalyzing stdin\x1b[0m"
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", stderr_output)
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(result, [])

    @patch('subprocess.Popen')
    def test_get_file_list_with_node_colors(self, mock_popen):
        stderr_output = """
        [\u001b[36mAnalyzing /path/to/file1.js\u001b[0m
        [\u001b[36mAnalyzing /path/to/file2.js\u001b[0m
        """
        mock_proc = Mock()
        mock_proc.communicate.return_value = ("", stderr_output)
        mock_popen.return_value = mock_proc
        
        result = esprima.get_file_list("module_name")
        
        self.assertEqual(len(result), 2)
        self.assertIn("/path/to/file1.js", result)
        self.assertIn("/path/to/file2.js", result)


class TestEsprimaPaths(unittest.TestCase):
    def test_main_js_path_exists(self):
        self.assertTrue(os.path.exists(esprima.main_js_path))

    def test_search_js_path_exists(self):
        self.assertTrue(os.path.exists(esprima.search_js_path))


class TestTypeScriptIntegration(unittest.TestCase):
    def test_typescript_stdin_can_be_selected_explicitly(self):
        output = esprima.esprima_parse(
            "-",
            args=["--typescript", "-o", "-"],
            input="const value: string = 'ok';\n",
        )

        self.assertIn("AST_ASSIGN", output)
        self.assertIn("value: string = 'ok'", output)

    def test_typescript_types_are_erased_and_locations_are_preserved(self):
        source = """interface RequestData {
  command: string
}

export function getCommand(input: RequestData): string {
  return input.command
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, "sample.ts")
            with open(file_path, "w", encoding="utf-8") as fp:
                fp.write(source)

            output = esprima.esprima_parse(file_path, args=["-o", "-"])

        self.assertIn("AST_FUNC_DECL", output)
        self.assertIn("getCommand", output)
        self.assertNotIn("ExportNamedDeclaration", output)
        function_rows = [line for line in output.splitlines() if "AST_FUNC_DECL" in line]
        self.assertEqual(len(function_rows), 1)
        self.assertEqual(function_rows[0].split("\t")[4], "5")

    def test_typescript_import_discovers_transitive_ts_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dependency = os.path.join(temp_dir, "dependency.ts")
            entry = os.path.join(temp_dir, "entry.ts")
            with open(dependency, "w", encoding="utf-8") as fp:
                fp.write("export const command: string = 'echo safe';\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import { command } from './dependency';\n"
                    "export const result: string = command;\n"
                )

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn(entry, output)
        self.assertIn(dependency, output)
        self.assertIn("./dependency", output)
        self.assertIn("require", output)
        self.assertNotIn("__importStar", output)

    def test_tsconfig_paths_are_resolved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = os.path.join(temp_dir, "src")
            os.makedirs(source_dir)
            entry = os.path.join(source_dir, "entry.ts")
            dependency = os.path.join(source_dir, "dependency.ts")
            with open(os.path.join(temp_dir, "tsconfig.json"), "w", encoding="utf-8") as fp:
                fp.write(
                    '{"compilerOptions":{"baseUrl":".",'
                    '"paths":{"@app/*":["src/*"]}}}'
                )
            with open(dependency, "w", encoding="utf-8") as fp:
                fp.write("export const value: number = 1;\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("import { value } from '@app/dependency';\nvoid value;\n")

            main_path, _ = esprima.esprima_search("@app/dependency", entry)

        self.assertEqual(main_path, dependency)

    def test_tsx_is_lowered_to_javascript_calls(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, "view.tsx")
            with open(file_path, "w", encoding="utf-8") as fp:
                fp.write(
                    "const name: string = 'probejs';\n"
                    "export const view = <div>{name}</div>;\n"
                )

            output = esprima.esprima_parse(file_path, args=["-o", "-"])

        self.assertIn("React.createElement", output)
        self.assertIn("AST_METHOD_CALL", output)

    def test_modern_typescript_constructs_are_lowered(self):
        source = """enum Mode { Safe, Unsafe }
class Service<T> {
  constructor(private fallback: T) {}
  get(value?: T): T { return value ?? this.fallback; }
}
const service = new Service<string>('safe');
service.get(undefined)?.toString();
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, "modern.ts")
            with open(file_path, "w", encoding="utf-8") as fp:
                fp.write(source)

            output = esprima.esprima_parse(file_path, args=["-o", "-"])

        self.assertIn("AST_CLASS", output)
        self.assertIn("AST_NEW", output)
        self.assertIn("BINARY_BOOL_OR", output)
        self.assertNotIn("ChainExpression", output)

    def test_source_level_module_normalization_covers_imports_and_reexports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dependency = os.path.join(temp_dir, "dependency.ts")
            barrel = os.path.join(temp_dir, "barrel.ts")
            entry = os.path.join(temp_dir, "entry.ts")
            with open(dependency, "w", encoding="utf-8") as fp:
                fp.write("export default 1; export const named = 2;\n")
            with open(barrel, "w", encoding="utf-8") as fp:
                fp.write("export * from './dependency';\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write(
                    "import fallback, * as values from './dependency';\n"
                    "export { named } from './barrel';\n"
                    "void fallback; void values.named;\n"
                )

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn("./dependency", output)
        self.assertIn("./barrel", output)
        self.assertIn("Object", output)
        self.assertIn("assign", output)
        self.assertNotIn("tslib", output)
        self.assertNotIn("__importStar", output)
        self.assertNotIn("__exportStar", output)
        self.assertIn(dependency, output)
        self.assertIn(barrel, output)

    def test_workspace_package_is_resolved_without_node_modules_symlink(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = os.path.join(temp_dir, "packages", "shared")
            app_dir = os.path.join(temp_dir, "apps", "web")
            os.makedirs(package_dir)
            os.makedirs(app_dir)
            with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"private":true,"workspaces":["packages/*","apps/*"]}')
            with open(os.path.join(package_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"name":"@workspace/shared","source":"src/index.ts"}')
            os.makedirs(os.path.join(package_dir, "src"))
            shared = os.path.join(package_dir, "src", "index.ts")
            with open(shared, "w", encoding="utf-8") as fp:
                fp.write("export const value = 1;\n")
            entry = os.path.join(app_dir, "entry.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("import { value } from '@workspace/shared'; void value;\n")

            main_path, _ = esprima.esprima_search("@workspace/shared", entry)

        self.assertEqual(main_path, shared)

    def test_workspace_exports_and_package_imports_are_resolved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = os.path.join(temp_dir, "packages", "shared")
            app_dir = os.path.join(temp_dir, "apps", "web")
            os.makedirs(os.path.join(package_dir, "src"))
            os.makedirs(os.path.join(app_dir, "src"))
            with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"private":true,"workspaces":["packages/*","apps/*"]}')
            with open(os.path.join(package_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write(
                    '{"name":"@workspace/shared","exports":'
                    '{"./feature":{"require":"./src/feature.ts"}}}'
                )
            feature = os.path.join(package_dir, "src", "feature.ts")
            with open(feature, "w", encoding="utf-8") as fp:
                fp.write("export const feature = true;\n")
            with open(os.path.join(app_dir, "package.json"), "w", encoding="utf-8") as fp:
                fp.write('{"imports":{"#local":"./src/local.ts"}}')
            local = os.path.join(app_dir, "src", "local.ts")
            entry = os.path.join(app_dir, "src", "entry.ts")
            with open(local, "w", encoding="utf-8") as fp:
                fp.write("export const local = true;\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("void 0;\n")

            exported_path, _ = esprima.esprima_search("@workspace/shared/feature", entry)
            imported_path, _ = esprima.esprima_search("#local", entry)

        self.assertEqual(exported_path, feature)
        self.assertEqual(imported_path, local)

    def test_project_references_are_loaded_and_original_project_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            library_dir = os.path.join(temp_dir, "library")
            app_dir = os.path.join(temp_dir, "app")
            os.makedirs(library_dir)
            os.makedirs(app_dir)
            library_config = os.path.join(library_dir, "tsconfig.json")
            app_config = os.path.join(app_dir, "tsconfig.json")
            library = os.path.join(library_dir, "index.ts")
            entry = os.path.join(app_dir, "index.ts")
            with open(library_config, "w", encoding="utf-8") as fp:
                fp.write('{"compilerOptions":{"composite":true},"include":["index.ts"]}')
            with open(app_config, "w", encoding="utf-8") as fp:
                fp.write(
                    '{"references":[{"path":"../library"}],'
                    '"compilerOptions":{"baseUrl":".","paths":{"library":["../library/index"]}},'
                    '"include":["index.ts"]}'
                )
            with open(library, "w", encoding="utf-8") as fp:
                fp.write("export const value: number = 1;\n")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("import { value } from 'library'; void value;\n")

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn(entry, output)
        self.assertIn(library, output)
        self.assertIn(app_config, output)

    def test_arkts_requires_vendor_compilation(self):
        source = """@Entry
@Component
struct Index {
  @State command: string = process.argv[2]
  build() {
    Column() {
      Text(this.command)
    }.width('100%')
  }
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, "Index.ets")
            with open(file_path, "w", encoding="utf-8") as fp:
                fp.write(source)

            with self.assertRaisesRegex(RuntimeError, "ArkTS .ets input is not supported"):
                esprima.esprima_parse(file_path, args=["-o", "-"])

    def test_type_metadata_marks_callback_call_sites(self):
        source = """declare function register(callback: (value: string) => void): void;
register((value: string) => console.log(value));
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, "callbacks.ts")
            with open(file_path, "w", encoding="utf-8") as fp:
                fp.write(source)

            output = esprima.esprima_parse(file_path, args=["-o", "-"])

        header, *rows = output.splitlines()
        callback_column = header.split("\t").index("typescript_callback_args")
        self.assertTrue(any(
            len(row.split("\t")) > callback_column and row.split("\t")[callback_column] == "0"
            for row in rows
        ))

    def test_tested_typescript_compiler_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entry = os.path.join(temp_dir, "entry.ts")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("export const value: string = 'ok';\n")

            output = esprima.esprima_parse(entry, args=["-o", "-"])

        self.assertIn("typescript/lib/typescript.js", output)
        self.assertIn('\\"version\\":\\"5.', output)

    def test_existing_inline_source_map_restores_original_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original = os.path.join(temp_dir, "original.ts")
            generated = os.path.join(temp_dir, "generated.js")
            with open(original, "w", encoding="utf-8") as fp:
                fp.write("const value: string = 'ok';\n")
            source_map = {
                "version": 3,
                "file": "generated.js",
                "sources": ["original.ts"],
                "names": [],
                "mappings": "AAAA",
            }
            encoded_map = base64.b64encode(json.dumps(source_map).encode()).decode()
            with open(generated, "w", encoding="utf-8") as fp:
                fp.write(
                    "const value = 'ok';\n"
                    "//# sourceMappingURL=data:application/json;base64," + encoded_map + "\n"
                )

            output = esprima.esprima_parse(generated, args=["-o", "-"])

        self.assertIn(original, output)

    def test_arkts_manifest_does_not_enable_heuristic_parsing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            module_root = os.path.join(temp_dir, "entry")
            source_root = os.path.join(module_root, "src", "main")
            os.makedirs(source_root)
            with open(os.path.join(temp_dir, "build-profile.json5"), "w", encoding="utf-8") as fp:
                fp.write("{ modules: [{ name: 'entry', srcPath: './entry' }], }")
            with open(os.path.join(temp_dir, "oh-package.json5"), "w", encoding="utf-8") as fp:
                fp.write("{ dependencies: { '@local/shared': 'file:../shared' } }")
            with open(os.path.join(source_root, "module.json5"), "w", encoding="utf-8") as fp:
                fp.write("{ module: { name: 'entry', abilities: [{ name: 'MainAbility', srcEntry: './ets/MainAbility.ets' }] } }")
            entry = os.path.join(source_root, "Index.ets")
            with open(entry, "w", encoding="utf-8") as fp:
                fp.write("@Entry @Component struct Index { build() { Text('ok') } }\n")

            with self.assertRaisesRegex(RuntimeError, "HarmonyOS toolchain"):
                esprima.esprima_parse(entry, args=["-o", "-"])

    def test_extended_tslib_model_contains_modern_helpers(self):
        tslib_path = os.path.join(get_builtin_packages_dir(), "tslib.js")
        with open(tslib_path, encoding="utf-8") as fp:
            model = fp.read()

        for helper in [
            "__esDecorate",
            "__classPrivateFieldGet",
            "__asyncGenerator",
            "__disposeResources",
            "__spreadArray",
            "__generator",
        ]:
            self.assertIn(helper, model)


if __name__ == "__main__":
    unittest.main()
