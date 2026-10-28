import io
import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import auto
from PureWaf import bypass
from PureWaf import utils
from PureWaf.PureWaf import PureWafConfig
from PureWaf.PureWaf import _configure_logger
from PureWaf.PureWaf import _execute_purewaf
from PureWaf.PureWaf import purewaf

try:
    from PureWaf.webui import MAX_ACTIVE_JOBS
    from PureWaf.webui import create_app
except Exception:
    MAX_ACTIVE_JOBS = None
    create_app = None


class UtilsRegressionTests(unittest.TestCase):
    def test_parse_waf_regex_supports_php_alternate_delimiters(self):
        hash_regex = utils.parse_waf_regex("#flag|cat#i")
        self.assertIsNotNone(hash_regex)
        self.assertTrue(hash_regex.search("CAT"))
        self.assertTrue(hash_regex.search("flag"))

        tilde_regex = utils.parse_waf_regex("~sys~m")
        self.assertIsNotNone(tilde_regex)
        self.assertTrue(tilde_regex.search("sys"))

    def test_parse_waf_regex_with_error_reports_invalid_pattern(self):
        compiled, error = utils.parse_waf_regex_with_error("/(unclosed/")
        self.assertIsNone(compiled)
        self.assertIn("not a valid regular expression", error)

        compiled, error = utils.parse_waf_regex_with_error("")
        self.assertIsNone(compiled)
        self.assertEqual(error, "")

    def test_parse_waf_chars_keeps_space_but_drops_line_breaks(self):
        chars = utils.parse_waf_chars(" /\r\n\t")
        self.assertIn(" ", chars)
        self.assertIn("/", chars)
        self.assertNotIn("\n", chars)
        self.assertNotIn("\t", chars)


class PayloadGenerationRegressionTests(unittest.TestCase):
    def _options(self, flagfile="/flag", read_env=False):
        return bypass.BypassOptions(
            flagfile=flagfile,
            read_env=read_env,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.4,
        )

    def test_generate_candidates_is_deterministic(self):
        first = bypass.generate_candidates(self._options())
        second = bypass.generate_candidates(self._options())
        self.assertEqual(first, second)
        self.assertGreater(len(first), 0)

    def test_base64_variable_split_is_stable_for_same_command(self):
        first = bypass._base64_pipe_bypass("cat /flag")
        second = bypass._base64_pipe_bypass("cat /flag")
        self.assertEqual(first, second)

    def test_flag_scope_does_not_include_root_listing_commands(self):
        flag_payloads = bypass.generate_candidates(self._options())
        self.assertNotIn("$'\\154\\163'", flag_payloads)
        self.assertIn("$'\\143\\141\\164\\40\\57\\146\\154\\141\\147'", flag_payloads)

    def test_env_octal_payload_only_when_read_env_requested(self):
        without_env = bypass.generate_candidates(self._options())
        self.assertNotIn("$'\\145\\156\\166'", without_env)

        with_env = bypass.generate_candidates(self._options(read_env=True))
        self.assertIn("$'\\145\\156\\166'", with_env)


class LoggerRegressionTests(unittest.TestCase):
    def test_quiet_does_not_replace_process_stdout(self):
        before = sys.stdout
        _configure_logger("QUIET")
        self.assertIs(sys.stdout, before)

    def test_invalid_waf_regex_is_reported_instead_of_silently_ignored(self):
        with patch("PureWaf.PureWaf.bypass.generate_candidates", return_value=[]):
            result = _execute_purewaf(
                PureWafConfig(waf_regex="/(unclosed/"),
                show_progress=False,
                sleep_before_run=False,
            )

        self.assertIn("not a valid regular expression", result.log_text)


class PublicApiRegressionTests(unittest.TestCase):
    def test_purewaf_returns_root_payload_when_no_flag_payload_exists(self):
        with (
            patch("PureWaf.PureWaf._configure_logger", return_value=(None, False)),
            patch("PureWaf.PureWaf.time.sleep", return_value=None),
            patch("PureWaf.PureWaf.bypass.generate_candidates", side_effect=[["root-seed"], ["flag-seed"]]),
            patch("PureWaf.PureWaf.bypass._build_targeted_candidates", side_effect=[["root-targeted"], ["flag-targeted"]]),
            patch("PureWaf.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
            patch("PureWaf.PureWaf.bypass.filter_payloads", side_effect=[[], ["root-ok"], [], []]),
        ):
            result = purewaf(log_level="INFO")

        self.assertEqual(result, "root-ok")


class AutoRegressionTests(unittest.TestCase):
    def test_direct_superglobal_filter_is_collected(self):
        source = """<?php
if (isset($_GET['cmd'])) {
    if (preg_match('/flag|cat|ls/i', $_GET['cmd'])) { die('no'); }
    system($_GET['cmd']);
}
"""
        result = auto.analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.waf_regex, "/flag|cat|ls/i")
        self.assertEqual(result.input_key, "cmd")

    def test_direct_superglobal_word_and_length_filters(self):
        source = """<?php
$cmd = $_POST['cmd'];
if (strpos($_POST['cmd'], 'flag') !== false) { die('no'); }
if (strlen($_POST['cmd']) > 20) { die('long'); }
system($cmd);
"""
        result = auto.analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_words, "flag")
        self.assertEqual(result.limit_length, 20)

    def test_php8_attribute_is_not_stripped_as_comment(self):
        source = """<?php
#[Route('/preview')]
function preview($p) { return $p; }
$c = $_GET['c'];
system($c);
"""
        stripped = auto._strip_php_comments(source)
        self.assertIn("#[Route('/preview')]", stripped)

    def test_unmapped_filter_construct_is_reported(self):
        source = """<?php
function waf($a, $b) { if (preg_match('/flag/i', $a)) die(); return $a; }
$c = $_GET['c'];
waf($c, 1);
system($c);
"""
        result = auto.analyze_php_auto(source)

        self.assertIn("could not be mapped", result.error)

    def test_reachable_unfiltered_sink_generates_instead_of_erroring(self):
        result = auto.analyze_php_auto("<?php eval($_POST['code']);")

        self.assertEqual(result.error, "")
        self.assertEqual(result.payload_context, "php_code")
        self.assertTrue(
            any("no WAF filter was detected" in line for line in result.analysis_lines)
        )

    def test_alternate_delimiter_regex_survives_auto_analysis(self):
        source = """<?php
$c = $_GET['c'];
if (preg_match('#flag|cat#i', $c)) die();
system($c);
"""
        result = auto.analyze_php_auto(source)

        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_regex, "#flag|cat#i")
        compiled = utils.parse_waf_regex(result.waf_regex)
        self.assertIsNotNone(compiled)
        self.assertTrue(compiled.search("CAT"))


class AgentPromptBudgetTests(unittest.TestCase):
    def test_review_prompt_truncates_oversized_source(self):
        from PureWaf.agent import MAX_LLM_REVIEW_SOURCE_BYTES
        from PureWaf.agent import PureWafProjectAgent

        messages = PureWafProjectAgent().build_payload_review_messages(
            source="x" * (MAX_LLM_REVIEW_SOURCE_BYTES + 5000),
            analysis_lines=[],
            shortest_root="N/A",
            shortest_flag="N/A",
            root_payloads=[],
            flag_payloads=[],
        )
        prompt = messages[1]["content"]

        self.assertIn("PUREWAF_PROMPT_TRUNCATED", prompt)
        self.assertLess(len(prompt), MAX_LLM_REVIEW_SOURCE_BYTES + 20_000)



class AgentAutoPathTests(unittest.TestCase):

    def _fixtures(self, analysis, review):
        from PureWaf.agent import ProjectSourceBundle
        from PureWaf.PureWaf import PureWafExecutionResult

        bundle = ProjectSourceBundle(
            root=ROOT,
            source="<?php system($_GET['c']);",
            analysis_lines=["[*] AGENT: bundle ready"],
        )
        result = PureWafExecutionResult(
            shortest_root="ls /",
            shortest_flag="cat /flag",
            root_passed_payloads=["ls /"],
            flag_passed_payloads=["cat /flag"],
            tips_text="",
            log_text="[+] Final Payload: cat /flag",
        )
        project_agent = MagicMock()
        project_agent.build_project_source.return_value = bundle
        project_agent.validate_payloads.return_value = []
        project_agent.review_payloads.return_value = review
        return project_agent, result

    def test_happy_path_returns_reviewed_payload(self):
        from PureWaf.PureWaf import PureWafConfig
        from PureWaf.PureWaf import _execute_agent_auto_from_project
        from PureWaf.agent import LlmPayloadReview
        from PureWaf.auto import AutoAnalysisResult

        analysis = AutoAnalysisResult(
            sink_kind="command_exec",
            sink_function="system",
            payload_context="shell_command",
            waf_regex="/flag/i",
            analysis_lines=["[*] AUTO: sink ok"],
        )
        review = LlmPayloadReview(
            used=True,
            valid=True,
            payload_value="cat /flag",
            source="purewaf",
            evidence="payload reaches system()",
        )
        project_agent, result = self._fixtures(analysis, review)

        with (
            patch("PureWaf.agent.PureWafProjectAgent", return_value=project_agent),
            patch("PureWaf.agent.PureWafAgentSession", return_value=MagicMock()),
            patch("PureWaf.auto.resolve_auto_parameters", return_value=analysis),
            patch("PureWaf.PureWaf._execute_purewaf", return_value=result),
        ):
            output = _execute_agent_auto_from_project(PureWafConfig(auto=True, agent=True))

        self.assertEqual(output, "cat /flag")
        project_agent.validate_payloads.assert_called_once()
        project_agent.review_payloads.assert_called_once()

    def test_analysis_error_falls_back_to_agent_payload(self):
        from PureWaf.PureWaf import PureWafConfig
        from PureWaf.PureWaf import _execute_agent_auto_from_project
        from PureWaf.agent import LlmPayloadReview
        from PureWaf.auto import AutoAnalysisResult

        analysis = AutoAnalysisResult(error="no supported sink")
        review = LlmPayloadReview(
            used=True,
            valid=False,
            payload_value="system('cat /flag');",
            source="llm_fallback",
        )
        project_agent, result = self._fixtures(analysis, review)

        with (
            patch("PureWaf.agent.PureWafProjectAgent", return_value=project_agent),
            patch("PureWaf.agent.PureWafAgentSession", return_value=MagicMock()),
            patch("PureWaf.auto.resolve_auto_parameters", return_value=analysis),
            patch("PureWaf.PureWaf._execute_purewaf", return_value=result) as execute_mock,
        ):
            output = _execute_agent_auto_from_project(PureWafConfig(auto=True, agent=True))

        self.assertEqual(output, "system('cat /flag');")
        execute_mock.assert_not_called()

    def test_llm_failure_is_reported_without_crashing(self):
        from PureWaf.PureWaf import PureWafConfig
        from PureWaf.PureWaf import _execute_agent_auto_from_project
        from PureWaf.auto import AutoAnalysisResult

        analysis = AutoAnalysisResult(llm_error="LLM request failed: timeout")
        project_agent, result = self._fixtures(analysis, MagicMock())

        with (
            patch("PureWaf.agent.PureWafProjectAgent", return_value=project_agent),
            patch("PureWaf.agent.PureWafAgentSession", return_value=MagicMock()),
            patch("PureWaf.auto.resolve_auto_parameters", return_value=analysis),
            patch("PureWaf.PureWaf._execute_purewaf", return_value=result),
        ):
            output = _execute_agent_auto_from_project(PureWafConfig(auto=True, agent=True))

        self.assertIn("LLM", output)

@unittest.skipIf(create_app is None, "Flask webui module not available")
class WebUiLimitTests(unittest.TestCase):
    def test_auto_runtime_config_reads_php_verify(self):
        from PureWaf.webui import _build_auto_runtime_config

        config = _build_auto_runtime_config({"php_verify": True}, PureWafConfig(webui=True))
        self.assertTrue(config.php_verify)

        disabled = _build_auto_runtime_config({}, PureWafConfig(webui=True))
        self.assertFalse(disabled.php_verify)

    def test_run_is_rejected_when_active_job_cap_is_reached(self):
        from PureWaf.PureWaf import PureWafConfig

        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()

        with patch("PureWaf.webui._JobStore.count_active", return_value=MAX_ACTIVE_JOBS):
            response = client.post("/api/run", json={"mode": "filter"})

        self.assertEqual(response.status_code, 429)


if __name__ == "__main__":
    unittest.main()
