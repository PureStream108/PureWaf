import logging
import unittest
from unittest.mock import patch

from PureWaf import PureWaf, auto, bypass, php_oracle, planner
from PureWaf.auto import AutoContext


class PlannerTests(unittest.TestCase):
    def test_generate_composes_operators(self):
        payloads = planner.generate("cat /work/flag", depth=3, max_candidates=200)
        self.assertTrue(any("''" in payload for payload in payloads), payloads[:5])
        self.assertTrue(any("${IFS}" in payload for payload in payloads), payloads[:5])
        self.assertTrue(any("?" in payload for payload in payloads), payloads[:5])
        self.assertTrue(any("base64 -d" in payload or "base64${IFS}-d" in payload for payload in payloads))

    def test_plan_for_options_skips_php_context(self):
        options = bypass.BypassOptions(
            flagfile="/work/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.3,
            payload_context="php_code",
            generator="planner",
        )
        self.assertEqual(planner.plan_for_options(options), [])

    def test_planner_payloads_reach_generate_candidates(self):
        options = bypass.BypassOptions(
            flagfile="/work/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.3,
            payload_context="shell_command",
            generator="hybrid",
        )
        payloads = bypass.generate_candidates(options)
        self.assertTrue(any("base64" in payload for payload in payloads))
        self.assertTrue(any("${IFS}" in payload for payload in payloads))


    def test_feedback_search_prefers_passing_operator(self):
        best = planner.feedback_search(
            "cat /work/flag",
            lambda batch: {payload for payload in batch if "base64" in payload},
            rounds=3,
            top_k=6,
        )
        self.assertIn("base64", best)

    def test_feedback_search_returns_empty_without_pass(self):
        self.assertEqual(
            planner.feedback_search(
                "cat /work/flag", lambda batch: set(), rounds=2, top_k=4
            ),
            "",
        )


class FeedbackIntegrationTests(unittest.TestCase):
    def test_verify_with_php_falls_back_to_feedback(self):
        config = PureWaf.PureWafConfig(
            flagfile="/work/flag",
            php_verify=True,
            php_source="<?php system($_GET['c']);",
            generator="hybrid",
            payload_context="shell_command",
            auto_context=AutoContext(
                sink_kind="command_exec",
                sink_function="system",
                input_source="GET",
                input_key="c",
            ),
        )

        def fake_run(*args, **kwargs):
            request = kwargs.get("request") or {}
            payload = ""
            for values in request.values():
                for value in values.values():
                    payload = str(value)
            return php_oracle.PhpRunResult(
                attempted=True,
                passed="base64" in payload,
                reason="ok" if "base64" in payload else "no",
            )

        with (
            patch(
                "PureWaf.php_oracle.environment_report",
                return_value={"available": True, "php_path": "php", "php_version": "8.3"},
            ),
            patch("PureWaf.php_oracle.docker_available", return_value=False),
            patch(
                "PureWaf.php_oracle.verify_payloads",
                return_value=php_oracle.PhpVerification(passed=False, reason="no"),
            ),
            patch("PureWaf.php_oracle.run_source", side_effect=fake_run),
        ):
            result = PureWaf._verify_with_php(
                config,
                "cat /work/flag",
                ["cat /work/flag"],
                [],
                logging.getLogger("test"),
            )
        self.assertIsNotNone(result)
        self.assertTrue(result.passed)
        self.assertIn("base64", result.payload)


class EngineSelectionTests(unittest.TestCase):
    SOURCE = """<?php
$c = $_GET['c'];
if (preg_match('/flag|cat/i', $c)) {
    die('blocked');
}
system($c);
"""

    def test_resolve_auto_parameters_both(self):
        result = auto.resolve_auto_parameters(self.SOURCE, engine="both")
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.sink_function, "system")
        self.assertIn("flag", result.waf_regex)
        self.assertEqual(result.input_key, "c")
        self.assertTrue(result.path_conditions)

    def test_resolve_auto_parameters_sast(self):
        result = auto.resolve_auto_parameters(self.SOURCE, engine="sast")
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.sink_function, "system")

    def test_resolve_auto_parameters_heuristic_default(self):
        result = auto.resolve_auto_parameters(self.SOURCE)
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.sink_function, "system")


if __name__ == "__main__":
    unittest.main()
