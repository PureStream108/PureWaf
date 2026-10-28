import os
import sys
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import auto
from PureWaf import bypass
from PureWaf import bypass_data
from PureWaf import utils
from PureWaf.auto import AutoContext


class CallbackSinkDetectionTests(unittest.TestCase):
    def test_ob_start_callable_injection(self):
        result = auto.analyze_php_auto("<?php ob_start($_GET['fn']); echo 'id'; ob_end_flush();")
        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.sink_function, "ob_start")
        self.assertEqual(result.payload_context, "php_code")

    def test_register_shutdown_function_callable_injection(self):
        result = auto.analyze_php_auto("<?php register_shutdown_function($_GET['fn']);")
        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_function, "register_shutdown_function")

    def test_preg_replace_callback_callable_injection(self):
        result = auto.analyze_php_auto("<?php preg_replace_callback('/.*/', $_GET['fn'], 'id');")
        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_function, "preg_replace_callback")

    def test_mb_ereg_replace_e_option(self):
        source = "<?php mb_ereg_replace('.*', $_GET['code'], 'x', 'e');"
        result = auto.analyze_php_auto(source)
        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_function, "mb_ereg_replace")
        self.assertEqual(result.payload_context, "php_code")

        explanation = bypass.describe_payload(source)
        self.assertEqual(explanation.max_php, "7.4")


class NewFilterDetectionTests(unittest.TestCase):
    def test_mb_ereg_regex_filter(self):
        source = "<?php $c=$_GET['c']; if (mb_ereg('flag', $c)) die(); system($c);"
        result = auto.analyze_php_auto(source)
        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_regex, "flag")

    def test_str_starts_with_word_filter(self):
        source = "<?php $c=$_GET['c']; if (str_starts_with($c,'cat')) die(); system($c);"
        result = auto.analyze_php_auto(source)
        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_words, "cat")

    def test_str_ends_with_word_filter(self):
        source = "<?php $c=$_GET['c']; if (str_ends_with($c,'flag')) die(); system($c);"
        result = auto.analyze_php_auto(source)
        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_words, "flag")

    def test_intval_and_filter_var_sanitizers(self):
        intval = auto.analyze_php_auto("<?php $c=intval($_GET['c']); system($c);")
        self.assertIn("intval", intval.sanitizers)

        filtered = auto.analyze_php_auto(
            "<?php $c=filter_var($_GET['c'], FILTER_SANITIZE_STRING); system($c);"
        )
        self.assertIn("filter_var", filtered.sanitizers)


class PayloadTechniqueTests(unittest.TestCase):
    def test_callback_payloads_are_generated_for_php_code(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.3,
            payload_context="php_code",
            auto_context=AutoContext(
                sink_kind="command_exec",
                sink_function="eval",
                input_key="code",
            ),
        )
        payloads = bypass.generate_candidates(options)
        self.assertTrue(any("call_user_func('system'" in item for item in payloads))
        self.assertTrue(any("ReflectionFunction" in item for item in payloads))
        self.assertTrue(any("Closure::fromCallable" in item for item in payloads))

    def test_eval_sink_does_not_emit_self_referential_eval_wrapper(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.3,
            payload_context="php_code",
            auto_context=AutoContext(
                sink_kind="command_exec",
                sink_function="eval",
                input_key="code",
            ),
        )
        payloads = bypass.generate_candidates(options)
        self.assertNotIn("eval($_GET['code']);", payloads)
        self.assertNotIn("eval($_POST['code']);", payloads)

    def test_stream_wrappers_are_not_shell_split(self):
        self.assertFalse(bypass._is_shell_style_payload("php://filter/read=convert.base64-encode/resource=/flag"))
        self.assertFalse(bypass._is_shell_style_payload("data://text/plain,<?php phpinfo();?>"))

        targeted = bypass._build_targeted_candidates(
            ["php://filter/read=convert.base64-encode/resource=/flag"],
            ["php:"],
            set(),
            utils.parse_waf_regex("/php:/i"),
            payload_context="file_path",
        )
        self.assertTrue(any("php://filter" in item for item in targeted))
        self.assertFalse(any("p''h''p://" in item for item in targeted))

    def test_include_templates_include_plain_path(self):
        self.assertIn("{path}", bypass_data.AUTO_PRECISE_INCLUDE_TEMPLATES)


if __name__ == "__main__":
    unittest.main()
