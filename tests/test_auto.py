import os
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf.auto import analyze_php_auto
from PureWaf.auto import resolve_auto_parameters
from PureWaf import bypass
from PureWaf import bypass_data
from PureWaf.agent import LlmSinkAnalysis
from PureWaf.agent import LlmSinkCandidate


class AutoModeTests(unittest.TestCase):
    def test_analyze_command_exec_regex_filter(self):
        source = """<?php
if(isset($_POST['cmd'])){
    $cmd = escapeshellcmd($_POST['cmd']);
    if(!preg_match('/ls|cat|flag/i', $cmd)) {
        system($cmd);
    }
}
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.waf_regex, "/ls|cat|flag/i")
        self.assertIn("[*] AUTO: detected sink => command_exec", result.analysis_lines)

    def test_llm_runs_before_local_sink_detection_and_can_fallback(self):
        source = """<?php
$cmd = $_GET['cmd'];
if(!preg_match('/cat|flag/i', $cmd)) {
    system($cmd);
}
"""

        with patch("PureWaf.auto._detect_llm_sink", return_value=None) as llm_mock:
            result = resolve_auto_parameters(source, use_llm=True)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        llm_mock.assert_called_once()

    def test_llm_metadata_can_be_used_even_when_local_sink_exists(self):
        source = """<?php
$cmd = $_GET['cmd'];
if(!preg_match('/cat|flag/i', $cmd)) {
    system($cmd);
}
"""
        analysis = LlmSinkAnalysis(
            enabled=True,
            used=True,
            model="unit-model",
            candidates=[
                LlmSinkCandidate(
                    function="system",
                    kind="command_exec",
                    payload_context="shell_command",
                    argument_index=0,
                    confidence=0.95,
                    evidence="system receives filtered user input",
                )
            ],
        )

        with patch("PureWaf.agent.PureWafLlmSinkAgent.analyze_php", return_value=analysis):
            result = resolve_auto_parameters(source, use_llm=True)

        self.assertEqual(result.error, "")
        self.assertTrue(result.llm_used)
        self.assertEqual(result.sink_function, "system")
        self.assertEqual(result.payload_context, "shell_command")
        self.assertIn("LLM sink candidate", "\n".join(result.analysis_lines))

    def test_llm_can_supply_custom_wrapper_sink_metadata(self):
        source = """<?php
function run_cmd($x){
    system($x);
}
$cmd = $_GET['cmd'];
if(!preg_match('/cat|flag/i', $cmd)) {
    run_cmd($cmd);
}
"""
        analysis = LlmSinkAnalysis(
            enabled=True,
            used=True,
            model="unit-model",
            candidates=[
                LlmSinkCandidate(
                    function="run_cmd",
                    kind="command_exec",
                    payload_context="shell_command",
                    argument_index=0,
                    confidence=0.92,
                    evidence="run_cmd forwards input to system",
                )
            ],
        )

        with patch("PureWaf.agent.PureWafLlmSinkAgent.analyze_php", return_value=analysis):
            result = resolve_auto_parameters(source, use_llm=True)

        self.assertEqual(result.error, "")
        self.assertTrue(result.llm_used)
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.sink_function, "run_cmd")
        self.assertEqual(result.payload_context, "shell_command")
        self.assertEqual(result.waf_regex, "/cat|flag/i")
        self.assertIn("LLM sink candidate", "\n".join(result.analysis_lines))

    def test_analyze_stripos_array_blacklist_words(self):
        source = """<?php
$forbidden = array('system', 'exec', 'passthru', 'shell_exec');
foreach ($forbidden as $bad) {
    if (stripos($spell, $bad) !== false) {
        die("blocked");
    }
}
if (stripos($spell, 'flag') !== false) {
    die("blocked");
}
system($spell);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertIn("system", result.waf_words.split("|"))
        self.assertIn("exec", result.waf_words.split("|"))
        self.assertIn("flag", result.waf_words.split("|"))

    def test_analyze_wrapper_function_for_upload_sink(self):
        source = """<?php
function check($input){
    if(preg_match("/'| |_|php|;|~|\\\\^|\\\\+|eval|{|}/i",$input)){
        die('hacker!!!');
    }else{
        return $input;
    }
}

function waf($input){
    if(is_array($input)){
        foreach($input as $key=>$output){
            $input[$key] = waf($output);
        }
    }else{
        $input = check($input);
    }
}

$data = $_GET["data"] ?? "";
waf($data);
file_put_contents("index.php", $data);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "file_write_upload")
        self.assertEqual(result.waf_regex, "/'| |_|php|;|~|\\^|\\+|eval|{|}/i")

    def test_analyze_file_get_contents_direct_input_sink(self):
        source = """<?php
echo file_get_contents($_GET['f']);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "file_read_path")

    def test_iconv_file_read_preserves_multi_input_and_upstream_filters(self):
        source = """<?php
$user = null;
if (isset($_COOKIE['user'])) {
    $user = @unserialize($_COOKIE['user']);
}
$f = (string)($_GET['f'] ?? "");
$rawPath = $user->basePath . $f;
if (preg_match('/flag|\\/flag|\\.\\.|php:|data:|expect:/i', $rawPath)) {
    die('blocked');
}
$convertedPath = @iconv($user->encoding, "UTF-8//IGNORE", $rawPath);
echo file_get_contents($convertedPath);
"""

        result = resolve_auto_parameters(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "file_read_path")
        self.assertIn("iconv", result.preprocessors)
        self.assertIn("$_COOKIE['user']", result.input_refs)
        self.assertIn("$_GET['f']", result.input_refs)
        self.assertEqual(result.sink_function, "file_get_contents")
        self.assertEqual(result.payload_context, "any")
        self.assertEqual(result.input_key, "f")

    def test_analyze_file_read_family_variants(self):
        for func in ("readfile", "highlight_file", "show_source"):
            with self.subTest(func=func):
                source = f"""<?php
$path = $_GET['f'];
if (strpos($path, 'flag') !== false) {{ die('blocked'); }}
{func}($path);
"""

                result = analyze_php_auto(source)

                self.assertEqual(result.error, "")
                self.assertEqual(result.sink_kind, "file_read_path")
                self.assertEqual(result.sink_function, func)
                self.assertIn("flag", result.waf_words.split("|"))

    def test_analyze_extracts_str_replace_char_filters_for_eval_sink(self):
        source = """<?php
$code = $_POST['code'];
$code = str_replace("(", "blocked", $code);
$code = str_replace(".", "dot", $code);
eval($code);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.payload_context, "php_code")
        self.assertEqual(result.waf_chars, "(.")

    def test_analyze_call_user_func_array_sink(self):
        source = """<?php
$cmd = $_POST['cmd'] ?? '';
if (preg_match('/system|exec|passthru|flag/i', $cmd)) {
    die("blocked");
}
$cb = "assert";
$args = array($cmd);
call_user_func_array($cb, $args);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.waf_regex, "/system|exec|passthru|flag/i")

    def test_analyze_callback_factory_sink(self):
        source = """<?php
$cmd = $_POST['cmd'] ?? '';
if (strpos($cmd, 'flag') !== false) {
    die("blocked");
}
$f = create_function('', $cmd);
$f();
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertIn("flag", result.waf_words.split("|"))

    def test_resolve_auto_parameters_selects_read_env_strategy(self):
        source = """<?php
$shell = $_GET['shell'] ?? '';
if (strlen($shell) > 30) {
    die("toolong");
}
if (preg_match('/[A-Za-z0-9_$]/', $shell)) {
    die("blocked");
}
eval($shell);
"""

        result = resolve_auto_parameters(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.limit_length, 30)
        self.assertEqual(result.waf_regex, "/[A-Za-z0-9_$]/")
        self.assertTrue(result.read_env)
        self.assertFalse(result.upload)

    def test_resolve_auto_parameters_uses_baseline_for_file_read_path(self):
        source = """<?php
echo file_get_contents($_GET['f']);
"""

        result = resolve_auto_parameters(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "file_read_path")
        self.assertFalse(result.read_env)
        self.assertFalse(result.upload)
        self.assertIn("[*] AUTO: strategy probe => baseline", result.analysis_lines)

    def test_analyze_rejects_multiple_filtered_inputs(self):
        # Two independently-filtered inputs concatenated without a fixed command
        # prefix => still cannot be mapped onto one PureWaf model.
        source = """<?php
$a = $_GET['a'];
$b = $_GET['b'];
if(preg_match("/ls|cat|flag/i", $a)) { die('x'); }
if(preg_match("/ls|cat|flag/i", $b)) { die('y'); }
$cmd = $a . $b;
system($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(
            result.error,
            "multiple filtered inputs cannot be mapped to one PureWaf model",
        )

    def test_detect_strstr_word_filter(self):
        source = """<?php
$cmd = $_POST['cmd'] ?? '';
if (strstr($cmd, 'flag') !== false) {
    die('blocked');
}
system($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertIn("flag", result.waf_words.split("|"))

    def test_detect_preg_match_all_regex(self):
        source = """<?php
$cmd = $_POST['cmd'];
if (preg_match_all('/cat|flag/i', $cmd)) { die('blocked'); }
system($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_regex, "/cat|flag/i")

    def test_detect_in_array_blacklist(self):
        source = """<?php
$cmd = $_POST['cmd'];
$bad = array('system', 'exec', 'flag');
if (in_array($cmd, $bad)) { die('blocked'); }
eval($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        words = result.waf_words.split("|")
        self.assertIn("system", words)
        self.assertIn("exec", words)
        self.assertIn("flag", words)

    def test_detect_strtolower_preprocessor(self):
        source = """<?php
$cmd = strtolower($_POST['cmd']);
if (strpos($cmd, 'flag') !== false) { die('blocked'); }
system($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertIn("strtolower", result.preprocessors)

    def test_detect_escapeshellcmd_triggers_arg_injection(self):
        source = """<?php
$cmd = escapeshellcmd($_POST['cmd']);
if (!preg_match('/cat|flag/i', $cmd)) {
    system($cmd);
}
"""

        result = resolve_auto_parameters(source)

        self.assertEqual(result.error, "")
        self.assertIn("escapeshellcmd", result.sanitizers)

    def test_detect_htmlspecialchars_adds_char_constraints(self):
        source = """<?php
$cmd = htmlspecialchars($_POST['cmd']);
if (strpos($cmd, 'flag') !== false) { die('blocked'); }
eval($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertIn("htmlspecialchars", result.sanitizers)
        # html special chars should add char constraints.
        for ch in "<>&":
            self.assertIn(ch, result.waf_chars)

    def test_detect_fixed_command_prefix_file(self):
        source = """<?php
$comm1 = $_GET['comm1'];
$comm2 = $_GET['comm2'];
if(preg_match("/flag|cat/i", $comm1)) { $comm1 = ""; }
if(preg_match("/flag|sh/i", $comm2)) { $comm2 = ""; }
$cmd = "file " . $comm1 . " " . $comm2;
system($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.fixed_command_prefix, "file")
        self.assertEqual(len(result.input_slots), 2)

    def test_multi_regex_merged_to_or(self):
        source = """<?php
$cmd = $_POST['cmd'];
if (preg_match('/system/i', $cmd)) { die('a'); }
if (preg_match('/flag/i', $cmd)) { die('b'); }
eval($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        # combined regex should contain both patterns.
        self.assertIn("system", result.waf_regex)
        self.assertIn("flag", result.waf_regex)

    def test_open_basedir_triggers_glob_bypass(self):
        source = """<?php
ini_set('open_basedir', '/var/www/html');
$cmd = $_POST['cmd'];
if (strpos($cmd, 'flag') !== false) { die('blocked'); }
eval($cmd);
"""

        result = resolve_auto_parameters(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.open_basedir, "/var/www/html")

    def test_disable_functions_records_list(self):
        source = """<?php
ini_set('disable_functions', 'system,exec,passthru');
$cmd = $_POST['cmd'];
if (strpos($cmd, 'flag') !== false) { die('blocked'); }
eval($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertIn("system", result.disable_functions)
        self.assertIn("exec", result.disable_functions)

    def test_php_version_hint_extracted(self):
        source = """<?php
if (version_compare(PHP_VERSION, '7.4', '<')) { die('too old'); }
$cmd = $_POST['cmd'];
if (strpos($cmd, 'flag') !== false) { die('blocked'); }
eval($cmd);
"""

        result = analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertAlmostEqual(result.php_version_hint, 7.4, places=2)

    def test_precise_eval_uses_known_input_key(self):
        source = """<?php
$cmd = $_POST['spell'];
if (strpos($cmd, 'flag') !== false) { die('blocked'); }
eval($cmd);
"""

        result = analyze_php_auto(source)
        self.assertEqual(result.error, "")
        self.assertEqual(result.input_key, "spell")

        ctx = result.to_context()
        ctx.sink_function = "eval"
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
            upload=False,
            payload_context=result.payload_context,
            auto_context=ctx,
        )
        candidates = bypass.generate_candidates(options)
        joined = "\n".join(candidates)
        self.assertIn("spell", joined)

    def test_argument_injection_appears_when_prefix_known(self):
        source = """<?php
$a = $_GET['a'];
if (preg_match('/flag/i', $a)) { $a = ''; }
system("file " . $a);
"""

        result = analyze_php_auto(source)
        self.assertEqual(result.error, "")
        self.assertEqual(result.fixed_command_prefix, "file")

        ctx = result.to_context()
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
            upload=False,
            payload_context=result.payload_context,
            auto_context=ctx,
        )
        candidates = bypass.generate_candidates(options)
        joined = "\n".join(candidates)
        self.assertTrue(
            any(c.startswith("file ") or c.startswith("-") for c in candidates),
            f"no argument-injection payload in candidates; sample={candidates[:5]}",
        )
        self.assertIn("/flag", joined)

    def test_auto_only_payloads_skipped_in_filter_mode(self):
        """FILTER 模式(auto_context=None)不得生成任何 AUTO_* 独占 payload。"""
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
            upload=False,
            payload_context="any",
            auto_context=None,
        )
        candidates = bypass.generate_candidates(options)
        joined = "\n".join(candidates)
        for gadget in bypass_data.AUTO_ESCAPESHELLCMD_GADGETS:
            self.assertNotIn(gadget, joined)

    def test_file_read_auto_payloads_generated_only_in_auto_mode(self):
        from PureWaf.auto import AutoContext

        ctx = AutoContext(
            sink_function="file_get_contents",
            input_refs=["$_GET['f']"],
            input_key="f",
        )
        options_auto = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
            upload=False,
            payload_context="any",
            auto_context=ctx,
        )
        candidates_auto = bypass.generate_candidates(options_auto)
        self.assertIn("/flag", candidates_auto)
        self.assertIn(
            "php://filter/read=convert.base64-encode/resource=/flag",
            candidates_auto,
        )
        self.assertIn(
            "php://filter/convert.iconv.utf-8.utf-16le/resource=/flag",
            candidates_auto,
        )

        options_filter = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
            upload=False,
            payload_context="any",
            auto_context=None,
        )
        candidates_filter = bypass.generate_candidates(options_filter)
        self.assertNotIn("/flag", candidates_filter)
        self.assertNotIn(
            "php://filter/read=convert.base64-encode/resource=/flag",
            candidates_filter,
        )
        self.assertNotIn(
            "php://filter/convert.iconv.utf-8.utf-16le/resource=/flag",
            candidates_filter,
        )

    def test_auto_only_php7_emitted_only_when_version_ge_7(self):
        from PureWaf.auto import AutoContext

        ctx_v7 = AutoContext(
            sink_function="eval",
            input_refs=["$_POST['cmd']"],
            input_key="cmd",
            php_version_hint=7.2,
        )
        options_v7 = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
            upload=False,
            payload_context="any",
            auto_context=ctx_v7,
        )
        out_v7 = "\n".join(bypass.generate_candidates(options_v7))
        self.assertIn("'phpinfo'()", out_v7)

        ctx_v5 = AutoContext(sink_function="eval", php_version_hint=5.6)
        options_v5 = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=5.6,
            upload=False,
            payload_context="any",
            auto_context=ctx_v5,
        )
        out_v5 = "\n".join(bypass.generate_candidates(options_v5))
        self.assertNotIn("'phpinfo'()", out_v5)


if __name__ == "__main__":
    unittest.main()
