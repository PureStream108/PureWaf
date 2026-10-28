import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import php_oracle


class OracleInternalTests(unittest.TestCase):
    def test_runtime_ini_quotes_open_basedir(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = php_oracle._write_runtime_ini("php", Path(tmp), ["C:/a", "C:/b"])
            text = ini.read_text(encoding="utf-8")
        self.assertIn('open_basedir="C:/a', text)
        self.assertIn("C:/b\"", text)
        self.assertIn("allow_url_include=1", text)

    def test_rewrite_flag_paths(self):
        rewritten = php_oracle._rewrite_flag_paths(
            "cat /flag; include '/flag';", "/flag", Path("/work/flag")
        )
        self.assertIn("/work/flag", rewritten)
        self.assertNotIn("cat /flag", rewritten)

    def test_build_runner_sets_superglobals(self):
        runner = php_oracle._build_runner({})
        for token in (
            "$_GET",
            "$_POST",
            "$_COOKIE",
            "$_REQUEST",
            "getallheaders",
            "$__entry",
            "require $__entry",
        ):
            self.assertIn(token, runner)

    def test_candidate_paths_accepts_explicit_file_and_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "php.exe"
            exe.write_text("", encoding="utf-8")
            self.assertIn(str(exe), list(php_oracle._candidate_paths(str(exe))))
            self.assertIn(str(exe), list(php_oracle._candidate_paths(str(root))))

    def test_probe_php_invalid_binary(self):
        version, extensions = php_oracle.probe_php(str(Path("does-not-exist-php")))
        self.assertEqual(version, "")
        self.assertEqual(extensions, ())


class OracleDockerTests(unittest.TestCase):
    def setUp(self):
        php_oracle._docker_cache.clear()

    def tearDown(self):
        php_oracle._docker_cache.clear()

    def test_docker_available_uses_inspect(self):
        with patch("PureWaf.php_oracle.subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            self.assertTrue(php_oracle.docker_available("test-image"))
            run_mock.assert_called_once()
            self.assertTrue(php_oracle.docker_available("test-image"))
            self.assertEqual(run_mock.call_count, 1)

    def test_run_source_without_docker_reports_skip(self):
        with patch("PureWaf.php_oracle.docker_available", return_value=False):
            result = php_oracle.run_source("<?php echo 1;", runtime="docker")
        self.assertFalse(result.attempted)
        self.assertIn("docker runtime unavailable", result.reason)

    def test_verify_payloads_docker_branch(self):
        fake = php_oracle.PhpRunResult(attempted=True, passed=True, exit_code=0, stdout="FLAG")
        with (
            patch("PureWaf.php_oracle.docker_available", return_value=True),
            patch("PureWaf.php_oracle.run_source", return_value=fake) as run_mock,
        ):
            verification = php_oracle.verify_payloads(
                "<?php echo 1;",
                ["payload"],
                input_source="GET",
                input_key="cmd",
                runtime="docker",
                max_placements=1,
            )
        self.assertTrue(verification.passed)
        self.assertEqual(verification.placement, "GET[cmd]")
        run_mock.assert_called_once()

    def test_install_portable_is_windows_only(self):
        with patch("PureWaf.php_oracle.sys.platform", "linux"), redirect_stdout(io.StringIO()) as out:
            result = php_oracle.install_portable_php(quiet=False)
        self.assertIsNone(result)
        self.assertIn("Windows-only", out.getvalue())


class OracleCliTests(unittest.TestCase):
    def test_cli_env_report(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = php_oracle._main(["--env"])
        self.assertEqual(code, 0)
        self.assertIn("available", buffer.getvalue())

    def test_cli_requires_source_and_payload(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
                php_oracle._main([])


if __name__ == "__main__":
    unittest.main()
