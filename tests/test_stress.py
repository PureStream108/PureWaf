import json
import os
import re
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import bypass
from PureWaf import utils
from PureWaf.PureWaf import PureWafConfig
from PureWaf.PureWaf import PureWafExecutionResult
from PureWaf.auto import AutoContext
from PureWaf.auto import resolve_auto_parameters

try:
    from PureWaf.webui import STREAM_LINE_BATCH_SIZE
    from PureWaf.webui import create_app
except Exception:
    STREAM_LINE_BATCH_SIZE = None
    create_app = None


class PureWafStressTests(unittest.TestCase):
    def _extract_sse_payloads(self, body):
        payloads = []
        for chunk in body.split("\n\n"):
            if not chunk.startswith("data: "):
                continue
            payloads.append(json.loads(chunk[6:]))
        return payloads

    def test_large_payload_filtering_reports_progress_and_keeps_counts(self):
        payloads = []
        expected_passed = []
        for idx in range(1250):
            allowed = f"id_{idx}"
            expected_passed.append(allowed)
            payloads.extend(
                [
                    allowed,
                    f"cat /flag {idx}",
                    f"echo${{IFS}}/flag_{idx}",
                    f"printf blocked_{idx};",
                    ("x" * 32) + str(idx),
                ]
            )

        progress_events = []
        trace_events = []
        passed = bypass.filter_payloads(
            payloads,
            waf_words=["cat"],
            waf_chars={";"},
            waf_regex=re.compile(r"flag_[0-9]+"),
            limit_length=20,
            show_progress=False,
            verbose=False,
            progress_callback=progress_events.append,
            trace_callback=trace_events.append,
        )

        self.assertEqual(passed, expected_passed)
        self.assertEqual(len(trace_events), len(payloads))
        self.assertEqual(progress_events[0]["current"], 1)
        self.assertEqual(progress_events[-1]["current"], len(payloads))
        self.assertEqual(progress_events[-1]["passed"], len(expected_passed))
        self.assertIn(100, {event["current"] for event in progress_events})
        self.assertIn(5000, {event["current"] for event in progress_events})
        self.assertTrue(any(not event["allowed"] for event in trace_events))

    def test_targeted_candidate_generation_dedupes_large_repeated_pool(self):
        base_payloads = ["cat /flag", "system cat /flag", "echo test", "printf hello"] * 750

        targeted = bypass._build_targeted_candidates(
            base_payloads,
            waf_words=["cat"],
            waf_chars={" "},
            waf_regex=re.compile("flag"),
            payload_context="shell_command",
        )

        self.assertEqual(len(targeted), len(set(targeted)))
        self.assertLess(len(targeted), 100)
        self.assertIn("cat${IFS}/flag", targeted)
        self.assertIn("cat%09/flag", targeted)
        self.assertIn("c''a''t /f''l''a''g", targeted)

    def test_generate_candidates_stress_matrix_across_versions_and_contexts(self):
        versions = ["5.6", "7.4", "8.0", "8.3.18", "8.5.5"]
        contexts = ["any", "php_code", "shell_command", "file_path"]

        for version in versions:
            parsed_version = utils.parse_php_version(version)
            for payload_context in contexts:
                with self.subTest(version=version, payload_context=payload_context):
                    auto_context = None
                    if payload_context == "file_path":
                        auto_context = AutoContext(
                            sink_kind="file_read_path",
                            sink_function="file_get_contents",
                            input_key="f",
                            preprocessors=["urldecode", "rawurldecode"],
                        )

                    options = bypass.BypassOptions(
                        flagfile="/flag",
                        read_env=False,
                        reflect_shell=True,
                        ip="127.0.0.1",
                        port=8080,
                        phpinfo=True,
                        php_version=version,
                        upload=False,
                        payload_context=payload_context,
                        auto_context=auto_context,
                    )
                    payloads = bypass.generate_candidates(options)
                    records = bypass.generate_candidate_records(options)
                    joined = "\n".join(payloads)

                    self.assertGreater(len(payloads), 0)
                    self.assertEqual(len(payloads), len(set(payloads)))
                    self.assertEqual(len(records), len(payloads))
                    if payload_context == "file_path":
                        self.assertFalse(any(p.startswith(("cat ", "tac ", "nl ")) for p in payloads))
                        self.assertNotIn("system(", joined)
                    if parsed_version >= utils.parse_php_version("8.0"):
                        self.assertNotIn("assert($_POST[x]);", payloads)
                        self.assertNotIn("create_function", joined)
                        self.assertNotIn("preg_replace('/.*/e'", joined)
                    if parsed_version < utils.parse_php_version("7.0"):
                        self.assertNotIn("'system'(", joined)
                        self.assertNotIn("'phpinfo'()", joined)

    def test_auto_analysis_large_php_source_keeps_sink_metadata(self):
        filler = [
            (
                f"function helper_{idx}($v) {{ "
                f"$x = str_replace('noop_{idx}', '', $v); "
                f"return trim($x); }}"
            )
            for idx in range(350)
        ]
        source = (
            "<?php\n"
            + "\n".join(filler)
            + """
$cmd = $_GET['cmd'] ?? '';
if (stripos($cmd, 'cat') !== false) {
    die('blocked');
}
if (preg_match('/flag|tac/i', $cmd)) {
    die('blocked');
}
system($cmd);
"""
        )

        result = resolve_auto_parameters(source)

        self.assertGreater(len(source), 20000)
        self.assertEqual(result.error, "")
        self.assertEqual(result.sink_kind, "command_exec")
        self.assertEqual(result.sink_function, "system")
        self.assertEqual(result.payload_context, "shell_command")
        self.assertEqual(result.input_key, "cmd")
        self.assertIn("cat", result.waf_words.split("|"))
        self.assertEqual(result.waf_regex, "/flag|tac/i")

    @unittest.skipIf(create_app is None or STREAM_LINE_BATCH_SIZE is None, "Flask webui module not available")
    def test_webui_stream_batches_large_filter_event_burst(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()
        total_events = STREAM_LINE_BATCH_SIZE * 3 + 17

        def fake_execute_purewaf(
            config,
            output_logger=None,
            show_progress=False,
            sleep_before_run=False,
            event_callback=None,
        ):
            self.assertIsNotNone(event_callback)
            for idx in range(1, total_events + 1):
                event_callback(
                    {
                        "type": "filter",
                        "scope": "flag",
                        "phase": "targeted",
                        "current": idx,
                        "total": total_events,
                        "payload": f"payload-{idx}",
                        "allowed": idx % 2 == 0,
                        "techniques": ["raw"],
                    }
                )
            return PureWafExecutionResult(
                shortest_root="root-ok",
                shortest_flag="flag-ok",
                root_passed_payloads=["root-ok"],
                flag_passed_payloads=["flag-ok"],
                tips_text="",
                log_text="[+] Final Payload: flag-ok",
            )

        with patch("PureWaf.webui._execute_purewaf", side_effect=fake_execute_purewaf):
            run_response = client.post("/api/run", json={"mode": "filter"})
            self.assertEqual(run_response.status_code, 200)
            job_id = run_response.get_json()["job_id"]
            stream_response = client.get(f"/api/events/{job_id}")
            self.assertEqual(stream_response.status_code, 200)
            body = stream_response.get_data(as_text=True)

        events = self._extract_sse_payloads(body)
        line_events = [event for event in events if event["kind"] == "lines"]
        result_events = [event for event in events if event["kind"] == "result"]

        self.assertEqual(len(result_events), 1)
        self.assertEqual(sum(len(event["lines"]) for event in line_events), total_events)
        self.assertTrue(all(len(event["lines"]) <= STREAM_LINE_BATCH_SIZE for event in line_events))
        self.assertIn("payload-1", line_events[0]["lines"][0])
        self.assertEqual(result_events[0]["result"]["shortest_flag"], "flag-ok")


if __name__ == "__main__":
    unittest.main()
