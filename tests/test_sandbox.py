import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import php_oracle


PHP_BIN = php_oracle.find_php_binary()


class SandboxConfigTests(unittest.TestCase):
    def test_sandbox_env_scrubs_secrets(self):
        os.environ["PUREWAF_TEST_SECRET"] = "DO_NOT_LEAK"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                env = php_oracle._sandbox_env(Path(tmp) / "home")
        finally:
            os.environ.pop("PUREWAF_TEST_SECRET", None)
        self.assertNotIn("PUREWAF_TEST_SECRET", env)
        self.assertEqual(env.get("PUREWAF_SANDBOX"), "1")
        self.assertEqual(env.get("HOME"), str(Path(tmp) / "home"))

    def test_runtime_ini_strict_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = php_oracle._write_runtime_ini(
                "php", Path(tmp), ["C:/work"], profile="strict"
            )
            text = ini.read_text(encoding="utf-8")
        self.assertIn("memory_limit=64M", text)
        self.assertIn("max_execution_time=5", text)
        self.assertIn('open_basedir="C:/work"', text)
        self.assertIn("allow_url_include=0", text)
        self.assertIn("ffi.enable=0", text)
        self.assertIn("disable_functions=", text)
        self.assertIn("system", text)
        self.assertIn("disable_classes=", text)

    def test_docker_ini_uses_work_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = php_oracle._write_docker_ini(Path(tmp), profile="trusted")
            text = ini.read_text(encoding="utf-8")
        self.assertIn('open_basedir="/work"', text)
        self.assertIn('sys_temp_dir="/work"', text)
        self.assertIn("allow_url_include=1", text)

    def test_docker_command_is_hardened(self):
        command = php_oracle._docker_command(
            Path("C:/tmp/sandbox"), "php:8.3-cli", False, "purewaf-test"
        )
        joined = " ".join(command)
        for flag in (
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 64",
            "--memory 256m",
            "--cpus 0.5",
            "--network none",
            "--name purewaf-test",
            "--init",
        ):
            self.assertIn(flag, joined)


@unittest.skipUnless(PHP_BIN, "php CLI not found")
class SandboxExecutionTests(unittest.TestCase):
    def test_child_env_does_not_contain_host_secret(self):
        os.environ["PUREWAF_TEST_SECRET"] = "DO_NOT_LEAK"
        try:
            result = php_oracle.run_source(
                "<?php echo getenv('PUREWAF_TEST_SECRET') ?: 'EMPTY';",
                php_bin=PHP_BIN,
            )
        finally:
            os.environ.pop("PUREWAF_TEST_SECRET", None)
        self.assertIn("EMPTY", result.stdout)
        self.assertNotIn("DO_NOT_LEAK", result.stdout)

    def test_strict_profile_disables_shell_functions(self):
        result = php_oracle.run_source(
            "<?php system('echo hi');", php_bin=PHP_BIN, profile="strict"
        )
        self.assertNotIn("hi", result.stdout)

    def test_trusted_profile_keeps_shell_functions(self):
        result = php_oracle.run_source(
            "<?php system('echo hi');", php_bin=PHP_BIN, profile="trusted"
        )
        self.assertIn("hi", result.stdout)

    def test_output_is_capped_and_flagged(self):
        result = php_oracle.run_source(
            "<?php echo str_repeat('A', 200000);", php_bin=PHP_BIN
        )
        self.assertLessEqual(len(result.stdout), php_oracle.MAX_OUTPUT_BYTES)
        self.assertTrue(result.output_truncated)

    def test_timeout_terminates_the_process(self):
        started = time.time()
        result = php_oracle.run_source(
            "<?php sleep(10);", php_bin=PHP_BIN, timeout=1.0
        )
        elapsed = time.time() - started
        self.assertTrue(result.timed_out)
        self.assertLess(elapsed, 8.0)

    def test_open_basedir_blocks_read_outside_sandbox(self):
        canary = Path(ROOT) / "sandbox-canary-read.txt"
        canary.write_text("HOST_SECRET_READ", encoding="utf-8")
        try:
            result = php_oracle.run_source(
                "<?php echo @file_get_contents(" + repr(str(canary)) + ");",
                php_bin=PHP_BIN,
            )
        finally:
            canary.unlink(missing_ok=True)
        self.assertNotIn("HOST_SECRET_READ", result.stdout)

    def test_open_basedir_blocks_write_outside_sandbox(self):
        target = Path(ROOT) / "sandbox-canary-write.txt"
        target.unlink(missing_ok=True)
        try:
            php_oracle.run_source(
                "<?php @file_put_contents(" + repr(str(target)) + ", 'ESCAPED');",
                php_bin=PHP_BIN,
            )
        finally:
            target.unlink(missing_ok=True)
        self.assertFalse(target.exists())

    def test_strict_profile_disables_network_and_fork(self):
        result = php_oracle.run_source(
            "<?php echo function_exists('fsockopen') ? 'NET_YES' : 'NET_NO';"
            "echo '|';"
            "echo function_exists('pcntl_fork') ? 'FORK_YES' : 'FORK_NO';",
            php_bin=PHP_BIN,
            profile="strict",
        )
        self.assertIn("NET_NO", result.stdout)
        self.assertIn("FORK_NO", result.stdout)

    def test_trusted_profile_keeps_network_helpers(self):
        result = php_oracle.run_source(
            "<?php echo function_exists('fsockopen') ? 'NET_YES' : 'NET_NO';",
            php_bin=PHP_BIN,
            profile="trusted",
        )
        self.assertIn("NET_YES", result.stdout)


if __name__ == "__main__":
    unittest.main()
