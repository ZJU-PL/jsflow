import os
import unittest
import tempfile
import shutil

from probejs.launcher import unittest_main


REGRESS_DIR = os.path.join(os.path.dirname(__file__), "..", "regress")
VULNERABILITY_DIR = os.path.join(REGRESS_DIR, "vulnerability_detection")

VULNERABILITY_FILES = {
    "code_execution.js",
    "nosql_injection.js",
    "os_command_injection.js",
    "path_traversal.js",
    "prototype_pollution.js",
    "xss_vulnerable.js",
}


class TestRegressFiles(unittest.TestCase):
    """Test probejs on all files in tests/regress."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_test(self, js_file, vul_type, should_detect=True):
        """Helper to run probejs on a file and check for vulnerabilities."""
        import argparse

        js_path = self._resolve_regress_path(js_file)
        
        # Create a wrapper file to require the module
        wrapper_name = f"test_{js_file.replace(os.sep, '_').replace('/', '_')}"
        test_file_name = os.path.join(self.temp_dir, wrapper_name)
        js_call_template = f"var main_func=require('{js_path}');"
        with open(test_file_name, "w") as f:
            f.write(js_call_template)

        # Initialize args with default values
        args = argparse.Namespace(
            single_branch=False,
            function_timeout=None,
            proto_pollution=False,
            int_prop_tampering=False,
            nfb=False,
            rcf=False,
            rcd=False,
            exploit=False,
            coarse_only=False,
        )
        
        result, G = unittest_main(
            test_file_name,
            vul_type=vul_type,
            original_path=js_path,
            args=args,
        )

        if should_detect:
            self.assertTrue(
                G.success_detect,
                f"Expected to detect {vul_type} in {js_file} but did not"
            )
        else:
            self.assertFalse(
                G.success_detect,
                f"Did not expect to detect {vul_type} in {js_file} but did"
            )

    def _resolve_regress_path(self, js_file):
        """Resolve benchmark paths across the current regress directory layout."""
        if os.path.isabs(js_file):
            return js_file

        if js_file in VULNERABILITY_FILES:
            return os.path.join(VULNERABILITY_DIR, js_file)

        return os.path.join(REGRESS_DIR, js_file)

    def test_path_traversal_detection(self):
        """Test path traversal detection on path_traversal.js."""
        self._run_test("path_traversal.js", "path_traversal", should_detect=True)

    def test_path_traversal_safe(self):
        """Test that path_traversal_safe.js does not detect path traversal."""
        self._run_test("precision/path_traversal_safe.js", "path_traversal", should_detect=False)

    def test_os_command_injection_detection(self):
        """Test OS command injection detection on os_command_injection.js."""
        self._run_test("os_command_injection.js", "os_command", should_detect=True)

    def test_os_command_safe(self):
        """Test that os_command_safe.js does not detect OS command injection."""
        self._run_test("precision/os_command_safe.js", "os_command", should_detect=False)

    def test_xss_vulnerable_detection(self):
        """Test XSS detection on xss_vulnerable.js."""
        self._run_test("xss_vulnerable.js", "xss", should_detect=True)

    def test_xss_safe(self):
        """Test that xss_safe.js does not detect XSS."""
        self._run_test("precision/xss_safe.js", "xss", should_detect=False)

    def test_code_execution_detection(self):
        """Test code execution detection on code_execution.js."""
        self._run_test("code_execution.js", "code_exec", should_detect=True)

    def test_nosql_injection_detection(self):
        """Test NoSQL injection detection on nosql_injection.js."""
        self._run_test("nosql_injection.js", "nosql", should_detect=True)

    def test_prototype_pollution_detection(self):
        """Test prototype pollution detection on prototype_pollution.js."""
        self._run_test("prototype_pollution.js", "proto_pollution", should_detect=True)

    def test_motivating_v3_detection(self):
        """Test OS command injection detection on motivating_v3.js."""
        self._run_test("flows/motivating_v3.js", "os_command", should_detect=True)


if __name__ == "__main__":
    unittest.main()
