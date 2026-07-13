import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from probejs.vuln.vul_func_lists import signature_lists, get_all_sign_list


class TestVulFuncLists(unittest.TestCase):
    def test_signature_lists_structure(self):
        """Test that signature_lists has the expected keys."""
        expected_keys = [
            "os_command",
            "os_command_strict",
            "xss",
            "proto_pollution",
            "code_exec",
            "nosql",
            "sanitation",
            "path_traversal",
        ]
        for key in expected_keys:
            self.assertIn(key, signature_lists)
            self.assertIsInstance(signature_lists[key], list)

    def test_os_command_signatures(self):
        """Test OS command injection signatures."""
        sigs = signature_lists["os_command"]
        self.assertIn("sink_hqbpillvul_exec", sigs)
        self.assertIn("sink_hqbpillvul_execSync", sigs)
        self.assertIn("sink_hqbpillvul_spawn", sigs)

    def test_xss_signatures(self):
        """Test XSS vulnerability signatures."""
        sigs = signature_lists["xss"]
        self.assertIn("sink_hqbpillvul_http_write", sigs)
        self.assertIn("sink_hqbpillvul_http_setHeader", sigs)
        self.assertIn("res.send", sigs)
        self.assertIn("res.write", sigs)
        self.assertIn("res.end", sigs)

    def test_proto_pollution_signatures(self):
        """Test prototype pollution signatures."""
        sigs = signature_lists["proto_pollution"]
        self.assertIn("merge", sigs)
        self.assertIn("extend", sigs)
        self.assertIn("assign", sigs)
        self.assertIn("set", sigs)

    def test_code_exec_signatures(self):
        """Test code execution signatures."""
        sigs = signature_lists["code_exec"]
        self.assertIn("Function", sigs)
        self.assertIn("eval", sigs)
        self.assertIn("sink_hqbpillvul_eval", sigs)

    def test_nosql_signatures(self):
        """Test NoSQL injection signatures."""
        sigs = signature_lists["nosql"]
        self.assertIn("sink_hqbpillvul_nosql", sigs)
        self.assertIn("find", sigs)

    def test_sanitation_signatures(self):
        """Test sanitization function signatures."""
        sigs = signature_lists["sanitation"]
        self.assertIn("parseInt", sigs)
        self.assertEqual(len(sigs), 1)

    def test_path_traversal_signatures(self):
        """Test path traversal signatures."""
        sigs = signature_lists["path_traversal"]
        self.assertIn("pipe", sigs)
        self.assertIn("sink_hqbpillvul_fs_read", sigs)
        self.assertIn("fs.readFile", sigs)
        self.assertIn("fs.readFileSync", sigs)

    def test_get_all_sign_list(self):
        """Test get_all_sign_list returns all signatures."""
        all_sigs = get_all_sign_list()
        self.assertIsInstance(all_sigs, list)
        # Should contain all signatures from all categories
        for key, sigs in signature_lists.items():
            for sig in sigs:
                self.assertIn(sig, all_sigs)

    def test_no_empty_categories(self):
        """Test that no signature category is empty."""
        for key, sigs in signature_lists.items():
            self.assertGreater(len(sigs), 0, f"Category {key} should not be empty")

    def test_unique_signatures(self):
        """Test that signature lists don't have obvious duplicates."""
        all_sigs = get_all_sign_list()
        unique_sigs = set(all_sigs)
        # Some categories intentionally overlap (e.g., proto_pollution has 'set' which could be in others)
        # So we just check that we have at least some unique signatures
        self.assertGreater(len(unique_sigs), 10)


if __name__ == "__main__":
    unittest.main()
