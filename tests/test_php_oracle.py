import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import php_oracle


PHP_BIN = php_oracle.find_php_binary()


@unittest.skipUnless(PHP_BIN, "php CLI not found")
class PhpOracleNativeTests(unittest.TestCase):
    def test_reads_flag_from_real_source(self):
        source = "<?php\n$f = $_GET['f'];\nif (preg_match('/blocked/i', $f)) { die('no'); }\necho file_get_contents($f);\n"
        with tempfile.TemporaryDirectory() as tmp:
            flag = Path(tmp) / "s3cr3t"
            flag.write_text(php_oracle.FLAG_MARKER, encoding="utf-8")
            result = php_oracle.run_source(
                source,
                request={"get": {"f": str(flag)}},
                php_bin=PHP_BIN,
                flag_path=str(flag),
            )
        self.assertTrue(result.attempted, result.reason)
        self.assertTrue(result.passed, result.reason + " | " + result.stdout + result.stderr)

    def test_verify_payloads_picks_passing_candidate(self):
        source = "<?php\n$f = $_GET['f'];\nif (preg_match('/s3cr3t/i', $f)) { die('no'); }\necho file_get_contents($f);\n"
        with tempfile.TemporaryDirectory() as tmp:
            flag = Path(tmp) / "other"
            flag.write_text(php_oracle.FLAG_MARKER, encoding="utf-8")
            verification = php_oracle.verify_payloads(
                source,
                [str(flag)],
                input_source="GET",
                input_key="f",
                php_bin=PHP_BIN,
                sandbox_flag=str(flag),
                flagfile=str(flag),
                max_placements=2,
            )
        self.assertTrue(verification.passed, verification.reason)
        self.assertEqual(verification.placement, "GET[f]")

    def test_project_verification_uses_entry_file(self):
        files = {
            "index.php": "<?php include __DIR__ . '/check.php';",
            "check.php": (
                "<?php $f=$_GET['f']; "
                "if (preg_match('/cat/i',$f)) die('blocked'); "
                "echo file_get_contents($f);"
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            flag = Path(tmp) / "flag"
            flag.write_text(php_oracle.FLAG_MARKER, encoding="utf-8")
            verification = php_oracle.verify_payloads(
                "",
                ["/flag"],
                input_source="GET",
                input_key="f",
                php_bin=PHP_BIN,
                sandbox_flag=str(flag),
                flagfile="/flag",
                project_files=files,
                entry="index.php",
                max_placements=1,
            )
        self.assertTrue(verification.passed, verification.reason)
        self.assertEqual(verification.placement, "GET[f]")

    def test_cli_verifies_source_with_host_php(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "challenge.php"
            source_path.write_text(
                "<?php echo file_get_contents($_GET['f']);", encoding="utf-8"
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = php_oracle._main(
                    ["--source", str(source_path), "--payload", "/flag", "--get", "f"]
                )
        self.assertEqual(code, 0, buffer.getvalue())
        self.assertIn('"passed": true', buffer.getvalue())

    def test_cli_reports_failure_without_flag_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "challenge.php"
            source_path.write_text("<?php die('blocked');", encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = php_oracle._main(
                    ["--source", str(source_path), "--payload", "id", "--get", "cmd"]
                )
        self.assertEqual(code, 1, buffer.getvalue())
        self.assertIn('"passed": false', buffer.getvalue())

    def test_missing_php_reports_skipped(self):
        result = php_oracle.run_source("<?php echo 1;", php_bin=str(Path("definitely-not-php")))
        self.assertFalse(result.attempted)
        self.assertIn("php CLI not found", result.reason)


class PhpOracleEnvironmentTests(unittest.TestCase):
    def test_environment_report_shape(self):
        report = php_oracle.environment_report()
        self.assertIn("available", report)
        self.assertIn("docker", report)
        if report["available"]:
            self.assertTrue(report["php_version"])
            self.assertTrue(report["php_path"])

    def test_select_entry_file_prefers_index(self):
        files = {
            "check.php": "<?php system($_GET['c']);",
            "index.php": "<?php include 'check.php';",
        }
        self.assertEqual(php_oracle.select_entry_file(files), "index.php")

    def test_safe_relpath_rejects_traversal(self):
        with self.assertRaises(ValueError):
            php_oracle._safe_relpath("../secret.php")
        with self.assertRaises(ValueError):
            php_oracle._safe_relpath("C:/windows/win.ini")
        self.assertEqual(php_oracle._safe_relpath("./a/b.php"), "a/b.php")

    def test_build_placements_uses_detected_key_first(self):
        placements = php_oracle.build_placements("POST", "code", "payload", max_placements=3)
        self.assertEqual(placements[0][0], "POST[code]")
        self.assertEqual(placements[0][1]["post"], {"code": "payload"})
        self.assertLessEqual(len(placements), 3)

    def test_build_placements_falls_back(self):
        placements = php_oracle.build_placements("", "", "payload")
        labels = [label for label, _request in placements]
        self.assertIn("GET[cmd]", labels)
        self.assertIn("POST[cmd]", labels)


if __name__ == "__main__":
    unittest.main()
